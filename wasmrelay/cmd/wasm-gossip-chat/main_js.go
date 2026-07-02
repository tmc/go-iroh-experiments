//go:build js

// Command wasm-gossip-chat is a go-iroh browser (js/wasm) gossip chat node.
// Each browser tab that loads it binds ONE relay-only iroh endpoint (the UDP/IP
// transport is compiled out via WithoutIPTransports, exactly like Rust iroh's
// #[cfg(wasm_browser)]), joins a shared gossip topic over the relay, and
// exchanges live chat messages with every other tab on the same topic. It is a
// genuine cross-tab demo: distinct wasm instances in distinct tabs, meeting only
// on the relay-carried gossip overlay, with no direct IP connectivity.
//
// The overlay self-heals: each node remembers every peer it meets and, if it
// ever drops to zero neighbors, re-dials them so the swarm reforms after the
// bootstrap peer disappears (e.g. the host tab closes).
//
// JS surface (installed on globalThis):
//
//	irohReady        -> {id, topic, name} once the node has joined
//	irohSend(text)   -> broadcast a chat line to the topic
//	irohNeighbors()  -> current direct-neighbor count
//
// The node calls back into JS irohOnEvent(kind, from, text) for every gossip
// event: kind is "self"|"msg"|"up"|"down"|"status"|"error".
package main

import (
	"context"
	"crypto/sha256"
	"fmt"
	"strings"
	"sync"
	"syscall/js"
	"time"

	"github.com/tmc/go-iroh/gossip"
	"github.com/tmc/go-iroh/iroh"
	"github.com/tmc/go-iroh/key"
	"github.com/tmc/go-iroh/netaddr"
	"github.com/tmc/go-iroh/relay"
)

// node holds the live browser gossip node so the JS-facing callbacks can reach it.
type node struct {
	ep       *iroh.Endpoint
	topic    *gossip.Topic
	name     string
	relayURL netaddr.RelayURL

	// known is the set of peers we can re-dial to rejoin the overlay: the
	// original bootstrap peer plus every peer we've since met. Guarded by mu
	// because the heal goroutine reads it while the event loop records into it.
	mu    sync.Mutex
	known map[key.EndpointID]netaddr.EndpointAddr
}

// remember records a peer we can later re-dial. Safe for concurrent use.
func (n *node) remember(id key.EndpointID) {
	if id.IsZero() || id == n.ep.ID() {
		return
	}
	n.mu.Lock()
	n.known[id] = netaddr.NewEndpointAddr(id).WithRelayURL(n.relayURL)
	n.mu.Unlock()
}

// healPeers snapshots the current re-dial candidate set.
func (n *node) healPeers() []netaddr.EndpointAddr {
	n.mu.Lock()
	defer n.mu.Unlock()
	peers := make([]netaddr.EndpointAddr, 0, len(n.known))
	for _, addr := range n.known {
		peers = append(peers, addr)
	}
	return peers
}

func main() {
	// run blocks until the topic is joined, then installs the JS callbacks and
	// pumps events forever. select{} keeps the wasm instance alive.
	go func() {
		if err := run(); err != nil {
			emit("error", "", err.Error())
			setStatus("fail", err.Error())
		}
	}()
	select {}
}

func run() error {
	// Long-lived: the tab stays open. Individual ops get their own short ctx.
	// Cancel on return so the heal and beacon goroutines stop if the event loop
	// ever ends (the topic closed).
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	q := query()
	relayRaw := q("relay")
	if relayRaw == "" {
		return fmt.Errorf("missing relay query")
	}
	relayURL, err := netaddr.ParseRelayURL(relayRaw)
	if err != nil {
		return fmt.Errorf("parse relay url: %w", err)
	}
	mode := relay.ModeCustom(relay.MapFromURLs(relayURL))

	// Topic is shared across all tabs; default keeps the demo one-click.
	topicName := q("topic")
	if topicName == "" {
		topicName = "go-iroh-browser-chat"
	}
	topicID := gossip.TopicID(sha256.Sum256([]byte(topicName)))

	name := q("name")
	if name == "" {
		name = "anon"
	}

	setStatus("running", "binding relay-only endpoint...")

	ep, err := iroh.Bind(ctx,
		iroh.WithRelayMode(mode),
		iroh.WithoutIPTransports(), // the keystone: no UDP/IP transport in the browser
		// Keep-alive every 3s refreshes the idle timer so a LIVE peer's link never
		// times out even while nobody is typing. The idle timeout (30s, matching
		// go-iroh's own relay default) then only reaps links that have gone
		// genuinely silent — e.g. a tab that was closed abruptly. A very long idle
		// timeout here would be a trap: a closed tab would linger as a phantom
		// neighbor for that whole window, keeping IsJoined true and suppressing the
		// heal loop while delivery is actually broken.
		iroh.WithTransportConfig(&iroh.QUICTransportConfig{
			KeepAlivePeriod: 3 * time.Second,
			MaxIdleTimeout:  30 * time.Second,
		}),
	)
	if err != nil {
		return fmt.Errorf("bind endpoint: %w", err)
	}

	g := gossip.NewGossip(ep)
	router, err := iroh.NewRouter(ep, map[string]iroh.ProtocolHandler{
		gossip.ALPN: g.Handler(),
	}, nil)
	if err != nil {
		return fmt.Errorf("router: %w", err)
	}
	_ = router // stays alive for the life of the tab

	onlineCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	setStatus("running", "connecting to relay...")
	if err := ep.Online(onlineCtx); err != nil {
		return fmt.Errorf("relay online: %w", err)
	}

	// Bootstrap: the host tab has no peer and just subscribes; joiner tabs pass
	// ?peer=<host-id> and bootstrap the overlay off it. Both then converge.
	var bootstrap []netaddr.EndpointAddr
	if peer := q("peer"); peer != "" {
		peerID, err := key.ParseEndpointID(peer)
		if err != nil {
			return fmt.Errorf("parse peer id: %w", err)
		}
		bootstrap = append(bootstrap, netaddr.NewEndpointAddr(peerID).WithRelayURL(relayURL))
	}

	var topic *gossip.Topic
	if len(bootstrap) > 0 {
		topic, err = g.SubscribeAndJoin(ctx, topicID, bootstrap)
	} else {
		topic, err = g.Subscribe(ctx, topicID, nil)
	}
	if err != nil {
		return fmt.Errorf("subscribe topic: %w", err)
	}

	n := &node{
		ep:       ep,
		topic:    topic,
		name:     name,
		relayURL: relayURL,
		known:    make(map[key.EndpointID]netaddr.EndpointAddr),
	}
	// Seed the re-dial set with the bootstrap peer (if any).
	for _, addr := range bootstrap {
		n.remember(addr.ID)
	}
	n.install()

	id := ep.ID().String()
	emit("self", id, name)
	js.Global().Set("irohReady", js.ValueOf(map[string]any{
		"id": id, "topic": topicName, "name": name,
	}))
	setStatus("pass", "joined topic "+topicName+" as "+id[:12]+"…")
	emit("status", "", "node online — id "+id[:12]+"… — share this tab's URL (it carries ?peer=) to add more tabs")

	// Heal the overlay: if we ever drop to zero neighbors, re-dial known peers so
	// a node that lost its link (host reloaded, relay blip, sole neighbor left)
	// rejoins the swarm on its own instead of sitting isolated forever. Because
	// the candidate set grows to include every peer we meet, healing survives the
	// original bootstrap peer disappearing.
	go n.heal(ctx)

	// Beacon: periodically announce ourselves on the topic. Every node that hears
	// a beacon remembers the sender as a re-dial candidate, so knowledge of who is
	// in the room spreads across the whole swarm — not just to the host. This is
	// what lets two joiners reconnect DIRECTLY after the host they bootstrapped off
	// disappears: by then each has heard the other's beacon (relayed through the
	// host while it was alive) and can re-dial it.
	go n.beacon(ctx)

	// Pump gossip events into JS forever. A chat line is wire-encoded "name|text".
	for ev, err := range topic.Events() {
		if err != nil {
			emit("error", "", err.Error())
			continue
		}
		switch ev.Kind {
		case gossip.Received:
			// DeliveredFrom is the LAST HOP, not the original author — for a relayed
			// message it is our forwarding neighbor, which we already know. Remember
			// it anyway (it is reachable), but the useful learning comes from
			// beacons, which carry the sender's true ID in the payload.
			n.remember(ev.DeliveredFrom)
			if origin, ok := parsePresence(ev.Content); ok {
				n.remember(origin) // learn the ORIGINAL sender across the whole swarm
				continue           // control beacon, not a chat line
			}
			from := ev.DeliveredFrom.String()
			who, text := splitMsg(string(ev.Content))
			emit("msg", from+"|"+who, text)
		case gossip.NeighborUp:
			n.remember(ev.Peer) // learn a peer we can re-dial to heal later
			emit("up", ev.Peer.String(), "")
		case gossip.NeighborDown:
			emit("down", ev.Peer.String(), "")
		}
	}
	return fmt.Errorf("topic closed")
}

// presencePrefix marks a beacon: a control broadcast carrying the sender's own
// endpoint ID so every receiver — however many hops away — learns the TRUE
// origin, not just the forwarding neighbor. Never rendered as chat. The NUL
// prefix keeps it from colliding with any real "name|text" line.
const presencePrefix = "\x00iroh-presence|"

// parsePresence returns the sender's endpoint ID if content is a beacon.
func parsePresence(content []byte) (key.EndpointID, bool) {
	s := string(content)
	if !strings.HasPrefix(s, presencePrefix) {
		return key.EndpointID{}, false
	}
	id, err := key.ParseEndpointID(strings.TrimPrefix(s, presencePrefix))
	if err != nil {
		return key.EndpointID{}, false
	}
	return id, true
}

// beacon periodically broadcasts this node's own ID so every node learns every
// other node's endpoint ID (relayed through whatever links currently exist).
// This turns a bootstrap star into a fully-known mesh, so heal can re-dial a
// surviving peer even after the original host is gone.
func (n *node) beacon(ctx context.Context) {
	msg := []byte(presencePrefix + n.ep.ID().String())
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		if !n.topic.IsJoined() {
			continue // no neighbors to carry the beacon; heal handles reconnect
		}
		bctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		_ = n.topic.Broadcast(bctx, msg)
		cancel()
	}
}

// heal watches neighbor count and re-dials known peers whenever the overlay
// collapses to zero. It backs off while healthy so a stable swarm costs nothing.
// A node with no known peers (a fresh host nobody has joined yet) has nothing to
// re-dial and heals passively when a joiner re-dials its stable endpoint ID.
func (n *node) heal(ctx context.Context) {
	const (
		checkEvery = 2 * time.Second
		settle     = 3 * time.Second // grace after a rejoin before trying again
	)
	ticker := time.NewTicker(checkEvery)
	defer ticker.Stop()
	var lastAttempt time.Time
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		if n.topic.IsJoined() {
			continue
		}
		peers := n.healPeers()
		if len(peers) == 0 {
			continue // nothing to re-dial yet
		}
		// Isolated. Do not hammer: leave a settle window between rejoin attempts.
		if !lastAttempt.IsZero() && time.Since(lastAttempt) < settle {
			continue
		}
		lastAttempt = time.Now()
		emit("status", "", fmt.Sprintf("overlay lost — re-dialing %d known peer(s) to rejoin…", len(peers)))
		jctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		err := n.topic.JoinPeers(jctx, peers)
		cancel()
		if err != nil {
			emit("status", "", "rejoin attempt failed: "+err.Error())
		}
	}
}

// install wires the JS-callable functions onto globalThis.
func (n *node) install() {
	js.Global().Set("irohSend", js.FuncOf(func(_ js.Value, args []js.Value) any {
		if len(args) < 1 {
			return false
		}
		text := args[0].String()
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			payload := n.name + "|" + text
			if err := n.topic.Broadcast(ctx, []byte(payload)); err != nil {
				emit("error", "", "broadcast: "+err.Error())
			}
		}()
		return true
	}))
	js.Global().Set("irohNeighbors", js.FuncOf(func(_ js.Value, _ []js.Value) any {
		return len(n.topic.Neighbors())
	}))
}

// splitMsg parses a "name|text" wire message into its parts.
func splitMsg(s string) (name, text string) {
	if i := strings.IndexByte(s, '|'); i >= 0 {
		return s[:i], s[i+1:]
	}
	return "anon", s
}

// emit calls back into JS irohOnEvent(kind, from, text) if present.
func emit(kind, from, text string) {
	fn := js.Global().Get("irohOnEvent")
	if fn.Type() != js.TypeFunction {
		return
	}
	fn.Invoke(kind, from, text)
}

func setStatus(status, detail string) {
	body := js.Global().Get("document").Get("body")
	body.Call("setAttribute", "data-status", status)
	body.Call("setAttribute", "data-detail", detail)
}

// query returns a lookup over the current location's query string.
func query() func(string) string {
	params := js.Global().Get("URLSearchParams").New(
		js.Global().Get("location").Get("search"),
	)
	return func(k string) string {
		v := params.Call("get", k)
		if v.Type() != js.TypeString {
			return ""
		}
		return v.String()
	}
}
