// Tlog-iroh runs the roles of a tlogiroh transparency log over real iroh
// endpoints.
//
// Usage:
//
//	tlog-iroh demo
//	tlog-iroh operator -origin <name> [-skey <key>] [-announce <d>] [-bind <addr>]
//	tlog-iroh witness -ticket <t> -operator-key <vkey> [-name <name>] [-skey <key>] [-sync <d>] [-bind <addr>]
//	tlog-iroh watch -ticket <t> -operator-key <vkey> -witness-key <vkey> [-witness-key <vkey>]... [-k <n>] [-head <file>] [-sync <d>] [-bind <addr>]
//	tlog-iroh get -ticket <t> -operator-key <vkey> -witness-key <vkey> [-witness-key <vkey>]... [-k <n>] -head <file> -index <n> [-bind <addr>]
//
// The demo subcommand runs the whole flow in one process on loopback: an
// operator publishing entries, a witness cosigning them, a client enforcing
// a one-witness policy and verifying an inclusion proof, and an equivocating
// twin log whose split view is detected and flooded as a proof.
//
// The other subcommands run the roles as separate processes. The operator
// prints its verifier key and a doc ticket, then appends one entry per line
// read from standard input, publishing and announcing a new checkpoint after
// each. A witness cosigns announcements whose consistency it can prove and
// rebroadcasts them. Watch prints every checkpoint the policy accepts and
// with -head persists the accepted head note to a file. Get restores a
// persisted head and writes one entry to standard output after verifying its
// inclusion proof.
//
// Generated note keys are ephemeral and printed at startup; pass the printed
// signing key back with -skey to keep an identity across runs. By default
// endpoints bind to IPv6 loopback; pass -bind to serve a reachable address.
package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"errors"
	"flag"
	"fmt"
	"log"
	"maps"
	"net/netip"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/tmc/go-iroh-experiments/tlogiroh"
	"github.com/tmc/go-iroh/blobs"
	"github.com/tmc/go-iroh/docs"
	"github.com/tmc/go-iroh/gossip"
	"github.com/tmc/go-iroh/iroh"
	"github.com/tmc/go-iroh/netaddr"
	"golang.org/x/mod/sumdb/note"
)

func usage() {
	fmt.Fprintf(os.Stderr, `usage:
	tlog-iroh demo
	tlog-iroh operator -origin <name> [-skey <key>] [-announce <d>] [-bind <addr>]
	tlog-iroh witness -ticket <t> -operator-key <vkey> [-name <name>] [-skey <key>] [-sync <d>] [-bind <addr>]
	tlog-iroh watch -ticket <t> -operator-key <vkey> -witness-key <vkey> [-witness-key <vkey>]... [-k <n>] [-head <file>] [-sync <d>] [-bind <addr>]
	tlog-iroh get -ticket <t> -operator-key <vkey> -witness-key <vkey> [-witness-key <vkey>]... [-k <n>] -head <file> -index <n> [-bind <addr>]
`)
	os.Exit(2)
}

func main() {
	log.SetFlags(0)
	log.SetPrefix("tlog-iroh: ")
	if len(os.Args) < 2 {
		usage()
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	var err error
	switch os.Args[1] {
	case "demo":
		err = runDemo(ctx, os.Args[2:])
	case "operator":
		err = runOperator(ctx, os.Args[2:])
	case "witness":
		err = runWitness(ctx, os.Args[2:])
	case "watch":
		err = runWatch(ctx, os.Args[2:])
	case "get":
		err = runGet(ctx, os.Args[2:])
	default:
		usage()
	}
	if err != nil && !errors.Is(err, context.Canceled) {
		log.Fatal(err)
	}
}

// A node is one iroh endpoint with gossip registered plus any extra
// protocol handlers.
type node struct {
	ep     *iroh.Endpoint
	gossip *gossip.Gossip
	router *iroh.Router
}

func bindNode(ctx context.Context, bind string, extra map[string]iroh.ProtocolHandler) (*node, error) {
	addr, err := netip.ParseAddrPort(bind)
	if err != nil {
		return nil, fmt.Errorf("parse bind address %q: %w", bind, err)
	}
	ep, err := iroh.Bind(ctx, iroh.WithBindAddr(addr))
	if err != nil {
		return nil, fmt.Errorf("bind endpoint: %w", err)
	}
	gg := gossip.NewGossip(ep)
	handlers := map[string]iroh.ProtocolHandler{gossip.ALPN: gg.Handler()}
	maps.Copy(handlers, extra)
	router, err := iroh.NewRouter(ep, handlers, nil)
	if err != nil {
		_ = ep.Shutdown(ctx)
		return nil, fmt.Errorf("new router: %w", err)
	}
	return &node{ep: ep, gossip: gg, router: router}, nil
}

func (n *node) addr() netaddr.EndpointAddr {
	return netaddr.NewEndpointAddr(n.ep.ID()).WithIP(n.ep.LocalAddr())
}

func (n *node) shutdown() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = n.router.Shutdown(ctx)
	n.gossip.Shutdown(ctx)
	_ = n.ep.Shutdown(ctx)
}

// blobStreamHandler serves every stream of a blobs-ALPN connection from a
// local store.
type blobStreamHandler struct {
	store blobs.Store
}

func (h blobStreamHandler) Accept(ctx context.Context, conn *iroh.Conn) error {
	return blobs.ServeBlobStreams(ctx, func(ctx context.Context) (blobs.BidiStream, error) {
		return conn.AcceptStream(ctx)
	}, h.store)
}

// signerFor returns a note signer from skey, or generates a fresh key named
// name and prints both halves so the identity can be reused with -skey.
func signerFor(skey, name string) (note.Signer, error) {
	if skey != "" {
		signer, err := note.NewSigner(skey)
		if err != nil {
			return nil, fmt.Errorf("parse signing key: %w", err)
		}
		return signer, nil
	}
	skey, vkey, err := note.GenerateKey(rand.Reader, name)
	if err != nil {
		return nil, fmt.Errorf("generate key: %w", err)
	}
	fmt.Printf("generated key %s\n", name)
	fmt.Printf("  verifier key: %s\n", vkey)
	fmt.Printf("  signing key:  %s  (keep secret; reuse with -skey)\n", skey)
	signer, err := note.NewSigner(skey)
	if err != nil {
		return nil, fmt.Errorf("parse generated key: %w", err)
	}
	return signer, nil
}

// stringList collects repeated string flags.
type stringList []string

func (l *stringList) String() string { return strings.Join(*l, ",") }

func (l *stringList) Set(s string) error { *l = append(*l, s); return nil }

func runOperator(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("operator", flag.ExitOnError)
	origin := fs.String("origin", "", "log origin (required)")
	skey := fs.String("skey", "", "note signing key (default: generate one)")
	announce := fs.Duration("announce", 5*time.Second, "checkpoint re-announce interval")
	bind := fs.String("bind", "[::1]:0", "UDP address to bind")
	fs.Parse(args)
	if *origin == "" {
		return errors.New("operator: -origin is required")
	}
	signer, err := signerFor(*skey, *origin)
	if err != nil {
		return err
	}
	op, err := tlogiroh.NewOperator(*origin, signer)
	if err != nil {
		return err
	}
	n, err := bindNode(ctx, *bind, map[string]iroh.ProtocolHandler{
		blobs.ALPN: blobStreamHandler{store: op.Blobs()},
		docs.ALPN:  &docs.Handler{Store: op.Doc(), BlobStore: op.Blobs()},
	})
	if err != nil {
		return err
	}
	defer n.shutdown()
	topic, err := n.gossip.Subscribe(ctx, tlogiroh.TopicID(*origin), nil)
	if err != nil {
		return fmt.Errorf("subscribe: %w", err)
	}
	defer topic.Close()

	ticket := op.Ticket([]netaddr.EndpointAddr{n.addr()})
	fmt.Printf("serving log %q at %v\n", *origin, n.ep.LocalAddr())
	fmt.Printf("  doc ticket: %s\n", ticket)
	fmt.Printf("\nrun a witness (note the verifier key it prints):\n")
	fmt.Printf("  tlog-iroh witness -ticket %s -operator-key '<operator verifier key>'\n", ticket)
	fmt.Printf("\nrun a watcher:\n")
	fmt.Printf("  tlog-iroh watch -ticket %s -operator-key '<operator verifier key>' -witness-key '<witness verifier key>'\n", ticket)
	fmt.Printf("\ntype entries, one per line:\n")

	go func() {
		ticker := time.NewTicker(*announce)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if err := op.Announce(ctx, topic); err != nil && !errors.Is(err, tlogiroh.ErrNoCheckpoint) && ctx.Err() == nil {
					log.Printf("announce: %v", err)
				}
			}
		}
	}()

	lines := make(chan string)
	go func() {
		defer close(lines)
		scanner := bufio.NewScanner(os.Stdin)
		for scanner.Scan() {
			select {
			case lines <- scanner.Text():
			case <-ctx.Done():
				return
			}
		}
	}()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case line, ok := <-lines:
			if !ok {
				fmt.Printf("input closed; serving until interrupted\n")
				<-ctx.Done()
				return ctx.Err()
			}
			index, err := op.Append(ctx, []byte(line))
			if err != nil {
				return err
			}
			if _, err := op.Publish(ctx); err != nil {
				return err
			}
			if err := op.Announce(ctx, topic); err != nil {
				return err
			}
			fmt.Printf("entry %d appended; published tree size %d\n", index, op.Size())
		}
	}
}

// openedLog is the read-side plumbing shared by witness, watch, and get: a
// bound endpoint, a doc replica of the timeline, and a Source fetching blobs
// from the operator named in the ticket.
type openedLog struct {
	node   *node
	origin string
	opKey  note.Verifier
	opAddr netaddr.EndpointAddr
	doc    *docs.MemoryStore
	src    tlogiroh.Source
	ticket docs.DocTicket
}

// openLog parses the ticket and operator key, binds an endpoint, and syncs
// the doc replica until the operator's author id is known. An empty origin
// defaults to the operator key name.
func openLog(ctx context.Context, ticketStr, operatorKey, origin, bind string) (*openedLog, error) {
	if ticketStr == "" || operatorKey == "" {
		return nil, errors.New("-ticket and -operator-key are required")
	}
	ticket, err := docs.ParseTicket(ticketStr)
	if err != nil {
		return nil, fmt.Errorf("parse ticket: %w", err)
	}
	nodes := ticket.Nodes()
	if len(nodes) == 0 {
		return nil, errors.New("ticket lists no nodes")
	}
	opKey, err := note.NewVerifier(operatorKey)
	if err != nil {
		return nil, fmt.Errorf("parse operator key: %w", err)
	}
	if origin == "" {
		origin = opKey.Name()
	}
	n, err := bindNode(ctx, bind, nil)
	if err != nil {
		return nil, err
	}
	l := &openedLog{
		node:   n,
		origin: origin,
		opKey:  opKey,
		opAddr: nodes[0],
		doc:    docs.NewMemoryStore(),
		ticket: ticket,
	}
	namespace := ticket.Capability().NamespaceID()
	author, err := l.waitAuthor(ctx, namespace)
	if err != nil {
		n.shutdown()
		return nil, err
	}
	l.src = tlogiroh.Source{
		Doc:       l.doc,
		Namespace: namespace,
		Author:    author,
		Get:       tlogiroh.DialBlobGetter(n.ep, l.opAddr),
	}
	return l, nil
}

// waitAuthor syncs the doc replica until it holds a timeline entry and
// returns that entry's author: the timeline is single-writer, so any entry
// names the operator's author id.
func (l *openedLog) waitAuthor(ctx context.Context, namespace docs.NamespaceID) (docs.AuthorID, error) {
	waited := false
	for {
		err := l.sync(ctx, namespace)
		if err == nil {
			for _, entry := range l.doc.Entries() {
				if entry.Entry.Namespace() == namespace {
					return entry.Entry.Author(), nil
				}
			}
			err = errors.New("timeline is empty")
		}
		if !waited {
			waited = true
			fmt.Printf("waiting for log timeline (%v)\n", err)
		}
		select {
		case <-ctx.Done():
			return docs.AuthorID{}, ctx.Err()
		case <-time.After(time.Second):
		}
	}
}

func (l *openedLog) sync(ctx context.Context, namespace docs.NamespaceID) error {
	_, err := docs.Sync(ctx, l.node.ep, l.opAddr, namespace, l.doc, nil, docs.DefaultSyncConfig())
	return err
}

// resyncLoop keeps the doc replica fresh; sync errors are transient and
// resolved by the next tick.
func (l *openedLog) resyncLoop(ctx context.Context, every time.Duration) {
	ticker := time.NewTicker(every)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			_ = l.sync(ctx, l.src.Namespace)
		}
	}
}

func (l *openedLog) subscribe(ctx context.Context) (*gossip.Topic, error) {
	topic, err := l.node.gossip.Subscribe(ctx, tlogiroh.TopicID(l.origin), l.ticket.Nodes())
	if err != nil {
		return nil, fmt.Errorf("subscribe: %w", err)
	}
	return topic, nil
}

func runWitness(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("witness", flag.ExitOnError)
	ticket := fs.String("ticket", "", "doc ticket printed by the operator")
	operatorKey := fs.String("operator-key", "", "operator verifier key")
	origin := fs.String("origin", "", "log origin (default: operator key name)")
	name := fs.String("name", "witness", "witness key name")
	skey := fs.String("skey", "", "note signing key (default: generate one)")
	syncEvery := fs.Duration("sync", 2*time.Second, "doc resync interval")
	bind := fs.String("bind", "[::1]:0", "UDP address to bind")
	fs.Parse(args)
	signer, err := signerFor(*skey, *name)
	if err != nil {
		return err
	}
	l, err := openLog(ctx, *ticket, *operatorKey, *origin, *bind)
	if err != nil {
		return err
	}
	defer l.node.shutdown()
	topic, err := l.subscribe(ctx)
	if err != nil {
		return err
	}
	defer topic.Close()
	go l.resyncLoop(ctx, *syncEvery)

	w := tlogiroh.NewWitness(signer, l.origin, l.opKey, l.src)
	go func() {
		ticker := time.NewTicker(*syncEvery)
		defer ticker.Stop()
		var last tlogiroh.Checkpoint
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if head, ok := w.Head(); ok && head != last {
					last = head
					fmt.Printf("cosigned checkpoint: size %d\n", head.Tree.N)
				}
			}
		}
	}()
	fmt.Printf("witnessing log %q\n", l.origin)
	return w.Run(ctx, topic)
}

// clientFor builds the K-of-N client shared by watch and get.
func clientFor(l *openedLog, witnessKeys []string, k int) (*tlogiroh.Client, error) {
	var witnesses []note.Verifier
	for _, key := range witnessKeys {
		v, err := note.NewVerifier(key)
		if err != nil {
			return nil, fmt.Errorf("parse witness key: %w", err)
		}
		witnesses = append(witnesses, v)
	}
	policy, err := tlogiroh.NewPolicy(l.origin, l.opKey, witnesses, k)
	if err != nil {
		return nil, err
	}
	return tlogiroh.NewClient(policy, l.src), nil
}

func runWatch(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("watch", flag.ExitOnError)
	ticket := fs.String("ticket", "", "doc ticket printed by the operator")
	operatorKey := fs.String("operator-key", "", "operator verifier key")
	origin := fs.String("origin", "", "log origin (default: operator key name)")
	var witnessKeys stringList
	fs.Var(&witnessKeys, "witness-key", "witness verifier key (repeatable)")
	k := fs.Int("k", 1, "required witness cosignatures")
	head := fs.String("head", "", "file persisting the accepted head note")
	syncEvery := fs.Duration("sync", 2*time.Second, "doc resync interval")
	bind := fs.String("bind", "[::1]:0", "UDP address to bind")
	fs.Parse(args)
	l, err := openLog(ctx, *ticket, *operatorKey, *origin, *bind)
	if err != nil {
		return err
	}
	defer l.node.shutdown()
	client, err := clientFor(l, witnessKeys, *k)
	if err != nil {
		return err
	}
	if *head != "" {
		if msg, err := os.ReadFile(*head); err == nil {
			if err := client.SetHead(msg); err != nil {
				return fmt.Errorf("restore head from %s: %w", *head, err)
			}
			cp, _ := client.Head()
			fmt.Printf("restored head: size %d\n", cp.Tree.N)
		}
	}
	topic, err := l.subscribe(ctx)
	if err != nil {
		return err
	}
	defer topic.Close()
	go l.resyncLoop(ctx, *syncEvery)

	fmt.Printf("watching log %q with policy %d of %d witnesses\n", l.origin, *k, len(witnessKeys))
	for cp, err := range client.Watch(ctx, topic) {
		if equiv, ok := errors.AsType[*tlogiroh.EquivocationError](err); ok {
			size, verr := tlogiroh.VerifyEquivocation(equiv.Proof, l.origin, l.opKey)
			if verr != nil {
				continue
			}
			fmt.Printf("EQUIVOCATION PROVEN: two signed checkpoints of size %d; log operator is not to be trusted\n", size)
			continue
		}
		if err != nil {
			continue
		}
		fmt.Printf("accepted checkpoint: size %d hash %v\n", cp.Tree.N, cp.Tree.Hash)
		if *head != "" {
			if err := os.WriteFile(*head, client.HeadNote(), 0o600); err != nil {
				return fmt.Errorf("persist head: %w", err)
			}
		}
	}
	return ctx.Err()
}

func runGet(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("get", flag.ExitOnError)
	ticket := fs.String("ticket", "", "doc ticket printed by the operator")
	operatorKey := fs.String("operator-key", "", "operator verifier key")
	origin := fs.String("origin", "", "log origin (default: operator key name)")
	var witnessKeys stringList
	fs.Var(&witnessKeys, "witness-key", "witness verifier key (repeatable)")
	k := fs.Int("k", 1, "required witness cosignatures")
	head := fs.String("head", "", "file holding the accepted head note (required)")
	index := fs.Int64("index", -1, "entry index to fetch (required)")
	bind := fs.String("bind", "[::1]:0", "UDP address to bind")
	fs.Parse(args)
	if *head == "" || *index < 0 {
		return errors.New("get: -head and -index are required")
	}
	msg, err := os.ReadFile(*head)
	if err != nil {
		return err
	}
	l, err := openLog(ctx, *ticket, *operatorKey, *origin, *bind)
	if err != nil {
		return err
	}
	defer l.node.shutdown()
	client, err := clientFor(l, witnessKeys, *k)
	if err != nil {
		return err
	}
	if err := client.SetHead(msg); err != nil {
		return fmt.Errorf("restore head from %s: %w", *head, err)
	}
	data, err := client.Entry(ctx, *index)
	if err != nil {
		return err
	}
	_, err = os.Stdout.Write(append(data, '\n'))
	return err
}

func runDemo(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("demo", flag.ExitOnError)
	fs.Parse(args)
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()

	const origin = "demo.tlogiroh/log"
	skey, vkey, err := note.GenerateKey(rand.Reader, origin)
	if err != nil {
		return err
	}
	signer, err := note.NewSigner(skey)
	if err != nil {
		return err
	}
	fmt.Printf("log %q\n  operator key: %s\n", origin, vkey)

	op, err := tlogiroh.NewOperator(origin, signer)
	if err != nil {
		return err
	}
	opNode, err := bindNode(ctx, "[::1]:0", map[string]iroh.ProtocolHandler{
		blobs.ALPN: blobStreamHandler{store: op.Blobs()},
		docs.ALPN:  &docs.Handler{Store: op.Doc(), BlobStore: op.Blobs()},
	})
	if err != nil {
		return err
	}
	defer opNode.shutdown()

	witnessNode, err := bindNode(ctx, "[::1]:0", nil)
	if err != nil {
		return err
	}
	defer witnessNode.shutdown()
	clientNode, err := bindNode(ctx, "[::1]:0", nil)
	if err != nil {
		return err
	}
	defer clientNode.shutdown()
	evilNode, err := bindNode(ctx, "[::1]:0", nil)
	if err != nil {
		return err
	}
	defer evilNode.shutdown()

	// The witness and client keep their own doc replicas and fetch blobs
	// from the operator on demand.
	witnessDoc := docs.NewMemoryStore()
	clientDoc := docs.NewMemoryStore()
	resync := func() error {
		for _, r := range []struct {
			ep    *iroh.Endpoint
			store *docs.MemoryStore
		}{{witnessNode.ep, witnessDoc}, {clientNode.ep, clientDoc}} {
			if _, err := docs.Sync(ctx, r.ep, opNode.addr(), op.Namespace(), r.store, nil, docs.DefaultSyncConfig()); err != nil {
				return fmt.Errorf("docs sync: %w", err)
			}
		}
		return nil
	}

	wskey, wvkey, err := note.GenerateKey(rand.Reader, "demo.tlogiroh/witness")
	if err != nil {
		return err
	}
	wsigner, err := note.NewSigner(wskey)
	if err != nil {
		return err
	}
	wverifier, err := note.NewVerifier(wvkey)
	if err != nil {
		return err
	}
	opVerifier, err := note.NewVerifier(vkey)
	if err != nil {
		return err
	}
	witness := tlogiroh.NewWitness(wsigner, origin, opVerifier, tlogiroh.Source{
		Doc:       witnessDoc,
		Namespace: op.Namespace(),
		Author:    op.Author(),
		Get:       tlogiroh.DialBlobGetter(witnessNode.ep, opNode.addr()),
	})
	fmt.Printf("witness\n  witness key:  %s\n", wvkey)

	policy, err := tlogiroh.NewPolicy(origin, opVerifier, []note.Verifier{wverifier}, 1)
	if err != nil {
		return err
	}
	client := tlogiroh.NewClient(policy, tlogiroh.Source{
		Doc:       clientDoc,
		Namespace: op.Namespace(),
		Author:    op.Author(),
		Get:       tlogiroh.DialBlobGetter(clientNode.ep, opNode.addr()),
	})

	opTopic, err := opNode.gossip.Subscribe(ctx, tlogiroh.TopicID(origin), nil)
	if err != nil {
		return err
	}
	defer opTopic.Close()
	bootstrap := []netaddr.EndpointAddr{opNode.addr()}
	witnessTopic, err := witnessNode.gossip.Subscribe(ctx, tlogiroh.TopicID(origin), bootstrap)
	if err != nil {
		return err
	}
	defer witnessTopic.Close()
	clientTopic, err := clientNode.gossip.Subscribe(ctx, tlogiroh.TopicID(origin), bootstrap)
	if err != nil {
		return err
	}
	defer clientTopic.Close()
	evilTopic, err := evilNode.gossip.Subscribe(ctx, tlogiroh.TopicID(origin), bootstrap)
	if err != nil {
		return err
	}
	defer evilTopic.Close()
	for _, topic := range []*gossip.Topic{witnessTopic, clientTopic, evilTopic, opTopic} {
		if err := topic.Joined(ctx); err != nil {
			return fmt.Errorf("topic join: %w", err)
		}
	}
	fmt.Printf("four endpoints joined the gossip topic on loopback\n\n")

	go witness.Run(ctx, witnessTopic)

	heads := make(chan tlogiroh.Checkpoint, 16)
	equivs := make(chan *tlogiroh.EquivocationError, 16)
	go func() {
		for cp, err := range client.Watch(ctx, clientTopic) {
			if equiv, ok := errors.AsType[*tlogiroh.EquivocationError](err); ok {
				equivs <- equiv
				continue
			}
			if err == nil {
				heads <- cp
			}
		}
	}()
	waitHead := func(size int64) error {
		for {
			select {
			case cp := <-heads:
				if cp.Tree.N == size {
					fmt.Printf("client accepted checkpoint: size %d hash %v\n", cp.Tree.N, cp.Tree.Hash)
					return nil
				}
			case <-ctx.Done():
				return fmt.Errorf("timed out waiting for checkpoint of size %d", size)
			}
		}
	}
	grow := func(to int64) error {
		for op.Size() < to {
			if _, err := op.Append(ctx, fmt.Appendf(nil, "entry %d at %s", op.Size(), time.Now().Format(time.RFC3339))); err != nil {
				return err
			}
		}
		if _, err := op.Publish(ctx); err != nil {
			return err
		}
		if err := resync(); err != nil {
			return err
		}
		fmt.Printf("operator published checkpoint of size %d and announced it\n", to)
		return op.Announce(ctx, opTopic)
	}

	// The operator announcement alone fails the one-witness policy; the
	// client accepts only the witness-cosigned rebroadcast.
	if err := grow(5); err != nil {
		return err
	}
	if err := waitHead(5); err != nil {
		return err
	}
	if err := grow(12); err != nil {
		return err
	}
	if err := waitHead(12); err != nil {
		return err
	}

	data, err := client.Entry(ctx, 7)
	if err != nil {
		return err
	}
	fmt.Printf("client verified inclusion of entry 7: %q\n\n", data)

	// An equivocating twin log signed by the same operator key: same size,
	// different content, announced from a fourth node.
	twin, err := tlogiroh.NewOperator(origin, signer)
	if err != nil {
		return err
	}
	for twin.Size() < 12 {
		if _, err := twin.Append(ctx, fmt.Appendf(nil, "twin entry %d", twin.Size())); err != nil {
			return err
		}
	}
	if _, err := twin.Publish(ctx); err != nil {
		return err
	}
	fmt.Printf("evil node announces a twin log of size 12 signed by the same operator key\n")
	if err := twin.Announce(ctx, evilTopic); err != nil {
		return err
	}
	select {
	case equiv := <-equivs:
		size, err := tlogiroh.VerifyEquivocation(equiv.Proof, origin, opVerifier)
		if err != nil {
			return fmt.Errorf("flooded proof does not verify: %w", err)
		}
		fmt.Printf("client proved equivocation at size %d and flooded the proof\n", size)
	case <-ctx.Done():
		return errors.New("timed out waiting for equivocation proof")
	}
	if head, ok := client.Head(); ok {
		fmt.Printf("client head is still size %d: the split view was refused\n", head.Tree.N)
	}
	return nil
}
