// Irciroh runs a local IRC server in front of an irciroh node, so that an
// unmodified IRC client can chat over iroh with no server anywhere.
//
// Usage:
//
//	irciroh serve [-listen 127.0.0.1:6667] [node flags]
//	irciroh invite [-listen 127.0.0.1:6667] <#channel>
//
// Serve takes the node flags:
//
//	[-bind [::]:0] [-key path] [-nick name] [-state dir] [-recall=false] [-relay=false] [-relay-server url] [-rendezvous=false]
//
// Serve prints its endpoint identity and listen address, then accepts IRC
// clients on the listen address. Every client shares the process's endpoint
// key, nick, and channels: one process is one IRC identity.
//
// The bridge answers CTCP VERSION, PING, CLIENTINFO and TIME addressed
// to it. A PART's reason is not sent on: the network carries none.
//
// Sharing the channels means a channel's secret is spent once per process
// rather than once per client. A JOIN carrying no ticket names a name and
// not a channel, and is answered with whatever channel the process has
// under that name - which is how a reconnecting client gets back what it
// had, and is also why -listen on anything but loopback hands a sealed
// channel to whoever can reach the port, by name alone.
//
// The IRC key parameter of JOIN carries an irciroh ticket, so
//
//	/join #go irciroh...
//
// joins through a ticket while /join #go joins a public channel with no
// bootstrap peer. Invite asks a running bridge for a ticket to a channel it
// has joined and prints it.
//
// With -key the endpoint key is read from a file, and generated and written
// there when the file does not exist, so the identity survives restarts.
// Without it the key is ephemeral.
//
// Durable state - who has been kicked, and the secret of each channel this
// node founded - lives in -state, by default a directory under the user
// config directory. Those secrets are credentials, so the directory is
// created 0700 and the file holding them 0600. With -state set to the empty
// string the node keeps nothing: a kicked member rejoins after a restart, and
// a founder that restarts mints a new secret, voiding every ticket it has
// handed out.
package main

import (
	"context"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/tmc/go-iroh-experiments/irciroh"
	"github.com/tmc/go-iroh/dns"
	"github.com/tmc/go-iroh/gossip"
	"github.com/tmc/go-iroh/iroh"
	"github.com/tmc/go-iroh/key"
	"github.com/tmc/go-iroh/netaddr"
	"github.com/tmc/go-iroh/relay"
)

func usage() {
	fmt.Fprintf(os.Stderr, `usage:
	irciroh serve [-listen 127.0.0.1:6667] [node flags]
	irciroh invite [-listen 127.0.0.1:6667] <#channel>
node flags:
	[-bind [::]:0] [-key path] [-nick name] [-state dir] [-recall=false] [-relay=false] [-relay-server url] [-rendezvous=false]
`)
	os.Exit(2)
}

func main() {
	log.SetFlags(0)
	log.SetPrefix("irciroh: ")
	if len(os.Args) < 2 {
		usage()
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	var err error
	switch os.Args[1] {
	case "serve":
		err = runServe(ctx, os.Args[2:])
	case "invite":
		err = runInvite(os.Args[2:])
	default:
		usage()
	}
	if err != nil && !errors.Is(err, context.Canceled) {
		log.Fatal(err)
	}
}

// defaultStateDir is where a node keeps its bans and channel secrets. It is
// under the user config directory because the secrets there are credentials:
// anyone holding one can join the channel it names. An empty result leaves
// the node stateless rather than failing, since a node with no durable state
// still works; it just forgets.
func defaultStateDir() string {
	dir, err := os.UserConfigDir()
	if err != nil {
		return ""
	}
	return filepath.Join(dir, "irciroh")
}

// announce says on standard error what this node is doing on the
// network, once, as it comes up.
//
// It exists because mcp used to read files and now dials. A command
// whose whole job was to look at a directory will, from the moment it
// keeps one, reach servers run by somebody else and publish an address
// to a public DNS. That is a reasonable thing for it to do and an
// unreasonable thing for it to do quietly, and the answer is not a flag
// - the flags that turn both off are already here - but a sentence
// naming the two services by name, since the point is to be able to
// find out what was reached rather than that something was.
//
// Standard error, because mcp's standard output is the protocol.
func (n *nodeFlags) announce(w io.Writer, id key.EndpointID) {
	var doing []string
	if n.relayServer != "" {
		doing = append(doing, "reaching peers through the relay server "+n.relayServer)
	} else if n.relay {
		doing = append(doing, "reaching peers through the public relay servers run by number0")
	}
	if n.rendezvous {
		doing = append(doing, "publishing its address to the pkarr DNS, where anyone can look it up")
	}
	if len(doing) == 0 {
		fmt.Fprintf(w, "irciroh: node %s is on this network only; peers that are not directly routable cannot reach it\n", id)
		return
	}
	fmt.Fprintf(w, "irciroh: node %s is %s\n", id, strings.Join(doing, " and "))
}

// keyInState points the endpoint key at the state directory, for a
// command whose identity is the point rather than the session. It is
// not what serve does: an IRC client attaches to a bridge and the
// person at it knows which one, where a directory is handed to a
// program that has only the pins others made to go on.
//
// Two files in this program are called key and only one of them is a
// secret. <dir>/key, in the chat directory, holds this node's public
// endpoint id, so that a reader can tell its own lines from somebody
// else's; it is safe to paste into a channel. <state>/key holds the
// private key that id comes from, and it is not.
//
// Both flags default, and the pair of defaults is one identity. A join
// started with neither is not a new node: it is this machine's node,
// the one in the default state directory, and so is every other one
// started the same way. Three separate harnesses wore the same endpoint
// id on one afternoon, on both sides of a protocol change, under two
// nicks - and the logs that recorded it cannot tell them apart, so
// every inference anybody keyed on that id was unsound. The flag help
// says so because the trap is in what the defaults do together, which
// is the one thing neither flag on its own can say.
//
// With -state empty the node has been asked to forget, and an identity
// that survived that would be a surprise. No key file is read or
// written, the endpoint mints a fresh one, and every pin anybody made
// of this node stops matching - which is worth saying out loud, since
// being pinnable is most of what a durable key is for.
func (n *nodeFlags) keyInState() {
	switch {
	case n.keyPath != "":
	case n.state != "":
		n.keyPath = filepath.Join(n.state, "key")
	default:
		fmt.Fprintf(os.Stderr, "irciroh: warning: no endpoint key file (-state \"\"); this node is a new identity every run, so no peer's pin of it survives a restart\n")
	}
}

// runServe binds an endpoint, starts a node, and serves IRC clients.
func runServe(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	listen := fs.String("listen", "127.0.0.1:6667", "IRC listen address")
	var nf nodeFlags
	nf.register(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	node, closeNode, err := nf.open(ctx)
	if err != nil {
		return err
	}
	defer closeNode()

	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", *listen, err)
	}
	fmt.Printf("endpoint %s\n", node.ID())
	fmt.Printf("listening for IRC clients on %s\n", ln.Addr())
	warnOpenListener(os.Stderr, ln.Addr())
	return newBridge(node).Serve(ctx, ln)
}

// warnOpenListener says so when the bridge can be reached from off this
// machine. The bridge has no authentication of its own - every client
// on it shares the node's identity, its channels and its secrets - so
// the listen address is the whole of the access rule, and a bare JOIN
// of a name this node holds a secret for opens that channel to whoever
// sent it. That is written down in the package comment, and a thing
// written down is not a thing anybody read.
func warnOpenListener(w io.Writer, addr net.Addr) {
	ap, err := netip.ParseAddrPort(addr.String())
	if err != nil || ap.Addr().IsLoopback() {
		return
	}
	fmt.Fprintf(w, "irciroh: warning: listening on %s, which is not loopback; anyone who can reach that address speaks as this node and can join its sealed channels by name\n", addr)
}

// nodeFlags are the flags of a command that owns an endpoint. Serve puts
// an IRC listener in front of its node and join keeps the conversation in
// files itself; everything up to the node is the same program, so they
// take the same flags and build it the same way.
type nodeFlags struct {
	bind       string
	keyPath    string
	nick       string
	state      string
	rendezvous bool
	relay      bool
	// relayServer names a relay server of our own, for a network where
	// the public ones are out of reach. Empty keeps -relay's default.
	relayServer string
	// recall is the history feature. The flag is not called -history
	// because wait and agent already have one, meaning the local log
	// from its beginning rather than what a peer can be asked for, and
	// one binary with two -history flags that mean different things is
	// worse than a name nobody guesses first.
	//
	// It is on by default. What it serves is a public channel's recent
	// lines, which anybody who guesses the name can already read off
	// the topic, so keeping them costs the channel no secrecy it had;
	// a sealed channel keeps nothing either way. What it buys is that
	// somebody who joins a conversation is shown the conversation,
	// which is what a channel is for. Off, every node keeps nothing
	// and every join starts at silence, which is not a quieter version
	// of the feature but its absence at both ends.
	recall bool
}

func (n *nodeFlags) register(fs *flag.FlagSet) {
	fs.StringVar(&n.bind, "bind", "[::]:0", "iroh endpoint bind address")
	fs.StringVar(&n.keyPath, "key", "", "endpoint key file; generated when missing, and defaulted to <state>/key by join")
	fs.StringVar(&n.nick, "nick", "", "nick to chat as")
	fs.StringVar(&n.state, "state", defaultStateDir(), "directory for durable state, and under join the identity too; empty forgets kicks and channel secrets on restart")
	fs.BoolVar(&n.rendezvous, "rendezvous", true, "find channels by name, and be found on them, through the public discovery service")
	fs.BoolVar(&n.relay, "relay", true, "reach peers through the public relay servers; without it only directly routable peers can be reached")
	fs.StringVar(&n.relayServer, "relay-server", "", "use this relay server instead of the public ones, e.g. http://127.0.0.1:18443")
	fs.BoolVar(&n.recall, "recall", true, "ask a public channel's peers what was said before joining, and keep recent lines to answer that for others")
}

// open binds an endpoint and starts a node on it. The returned function
// shuts down what open started, in the reverse order, and is what the
// caller defers.
func (n *nodeFlags) open(ctx context.Context) (*irciroh.Node, func(), error) {
	// A test that leaves -state alone gets the default, which is the
	// person's own directory: their endpoint key and the channel
	// secrets beside it. Binding on that is not a test node, it is
	// their node, joining what they are in, on the public relays -
	// which three separate harnesses did here on one afternoon before
	// anybody noticed, because nothing about it fails and the logs
	// that recorded it could not tell the wearers apart.
	//
	// The three tests that did it now name a -state of their own, but
	// naming it is a thing to remember, and the next test to call a
	// command that parses its own flags will forget in exactly the same
	// silent way. So the default is refused here instead: a test may
	// have any state directory it asks for and may not have this one.
	if testing.Testing() && n.state != "" && n.state == defaultStateDir() {
		return nil, nil, fmt.Errorf("refusing to open the user's own state directory %s from a test; pass -state", n.state)
	}
	bindAddr, err := netip.ParseAddrPort(n.bind)
	if err != nil {
		return nil, nil, fmt.Errorf("parse bind address %q: %w", n.bind, err)
	}
	opts := []iroh.Option{iroh.WithBindAddr(bindAddr)}
	if n.rendezvous {
		// Rendezvous hands back a member's endpoint id and whatever
		// addresses its record carried. Those go stale; the lookup
		// service is what turns an id back into a current address, and
		// an endpoint does none unless it is given one.
		lookup := &iroh.AddressLookupServices{}
		res, err := iroh.NewPkarrResolver(iroh.N0DNSPkarrRelayProd, nil)
		if err != nil {
			return nil, nil, fmt.Errorf("pkarr resolver: %w", err)
		}
		lookup.AddResolver(res)
		opts = append(opts, iroh.WithAddressLookup(lookup))
	}
	if n.relayServer != "" {
		u, err := netaddr.ParseRelayURL(n.relayServer)
		if err != nil {
			return nil, nil, fmt.Errorf("parse relay server %q: %w", n.relayServer, err)
		}
		opts = append(opts, iroh.WithRelayMode(relay.ModeCustomURLs(u)))
	} else if n.relay {
		// Relays are off by default in the endpoint, which makes a node
		// bound to the unspecified address reachable only by a peer that
		// already has a route to it - a LAN, in practice. A chat tool
		// whose tickets are meant to be shared needs more than that, so
		// this is on unless asked otherwise. It does mean talking to
		// servers run by number0.
		opts = append(opts, iroh.WithRelayMode(relay.ModeDefault()))
	}
	if n.keyPath != "" {
		sk, err := loadKey(n.keyPath)
		if err != nil {
			return nil, nil, err
		}
		opts = append(opts, iroh.WithSecretKey(sk))
	}
	ep, err := iroh.Bind(ctx, opts...)
	if err != nil {
		return nil, nil, fmt.Errorf("bind endpoint: %w", err)
	}
	var undo []func()
	stop := func() {
		for i := len(undo) - 1; i >= 0; i-- {
			undo[i]()
		}
	}
	// A failure after the endpoint is up has to take down what is
	// already up, since the caller is given nothing to defer.
	fail := func(err error) (*irciroh.Node, func(), error) {
		stop()
		return nil, nil, err
	}
	undo = append(undo, func() { ep.Shutdown(context.WithoutCancel(ctx)) })

	if n.rendezvous {
		// Rendezvous answers with an endpoint id. Something has to
		// turn ids back into addresses, and that only works if
		// endpoints publish theirs: the endpoint resolves, it does not
		// announce, so this does.
		pub, err := iroh.N0PkarrPublisher(ep.SecretKey(), nil)
		if err != nil {
			return fail(fmt.Errorf("pkarr publisher: %w", err))
		}
		undo = append(undo, func() { pub.Close() })
		go publishAddr(ctx, ep, pub)
	}

	g := gossip.NewGossip(ep)
	var nodeOpts []irciroh.Option
	if n.rendezvous {
		nodeOpts = append(nodeOpts, irciroh.WithRendezvous())
	}
	if n.state != "" {
		nodeOpts = append(nodeOpts, irciroh.WithStateDir(n.state))
	}
	if n.recall {
		nodeOpts = append(nodeOpts, irciroh.WithHistory())
	}
	node, err := irciroh.NewNode(ep, g, n.nick, nodeOpts...)
	if err != nil {
		return fail(err)
	}
	undo = append(undo, func() { node.Close() })
	n.announce(os.Stderr, node.ID())
	handlers := map[string]iroh.ProtocolHandler{
		gossip.ALPN:        g.Handler(),
		irciroh.ALPN:       node.Handler(),
		irciroh.InviteALPN: node.InviteHandler(),
	}
	if n.recall {
		// Answering is registered with asking rather than always. A
		// node that keeps no lines would accept the connection and
		// serve nothing, which costs a dial to learn and reads from
		// outside as a peer that has forgotten rather than one that
		// never kept anything.
		handlers[irciroh.HistoryALPN] = node.HistoryHandler()
	}
	router, err := iroh.NewRouter(ep, handlers, nil)
	if err != nil {
		return fail(fmt.Errorf("new router: %w", err))
	}
	undo = append(undo, func() { router.Shutdown(context.WithoutCancel(ctx)) })

	if n.state == "" {
		fmt.Fprintf(os.Stderr, "irciroh: warning: running without persistent state (-state \"\"); channel secrets and bans are ephemeral\n")
	}
	return node, stop, nil
}

// publishAddr keeps the endpoint's own address published for as long as
// the process runs, so a peer holding nothing but its id can still reach
// it. An address that stops being republished expires, which is what
// keeps a stale one from outliving the process that had it.
func publishAddr(ctx context.Context, ep *iroh.Endpoint, pub *iroh.PkarrPublisher) {
	addrs := ep.WatchAddr()
	for {
		addr, err := addrs.Updated(ctx)
		if err != nil {
			return
		}
		if len(addr.Addrs()) == 0 {
			continue
		}
		pub.Publish(dns.NewEndpointData(addr.Addrs()...))
	}
}

// runInvite asks a running bridge for a channel ticket and prints it.
func runInvite(args []string) error {
	fs := flag.NewFlagSet("invite", flag.ExitOnError)
	listen := fs.String("listen", "127.0.0.1:6667", "address of a running bridge")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		usage()
	}
	channel := fs.Arg(0)
	ticket, err := ask(*listen, "TICKET "+channel, ticketNotice)
	if err != nil {
		return fmt.Errorf("invite %s: %w", channel, err)
	}
	fmt.Println(ticket)
	return nil
}

// ticketNotice reports whether line is the bridge's answer to TICKET,
// and returns the ticket. Only the server's own notice to this
// connection counts: untagged, from the server's name exactly, and to a
// nick rather than a channel. Anything relayed from the network is a
// line somebody else wrote, and a ticket is a thing somebody would like
// to hand you.
func ticketNotice(line string) (string, bool) {
	rest, ok := strings.CutPrefix(line, ":"+serverName+" NOTICE ")
	if !ok {
		return "", false
	}
	target, text, ok := strings.Cut(rest, " :")
	if !ok || target == "" || strings.ContainsAny(target, " #&") {
		return "", false
	}
	if !strings.HasPrefix(text, irciroh.TicketKind) || strings.Contains(text, " ") {
		return "", false
	}
	return text, true
}

// loadKey reads an endpoint key, generating and writing one when the file
// does not exist.
//
// A key file that anyone but its owner can read is refused rather than
// repaired. Tightening the mode afterwards would put the file right and
// leave the secret wrong: whoever could read it has already had the
// chance, and a key that has been readable stays compromised however it
// is chmodded later. Saying so is the only useful thing to do about it.
func loadKey(path string) (key.SecretKey, error) {
	b, err := os.ReadFile(path)
	switch {
	case err == nil:
		info, err := os.Stat(path)
		if err != nil {
			return key.SecretKey{}, fmt.Errorf("stat key %s: %w", path, err)
		}
		if mode := info.Mode().Perm(); mode&0o077 != 0 {
			return key.SecretKey{}, fmt.Errorf("key %s is mode %#o and so is not a secret; move it aside and a new one is made", path, mode)
		}
		sk, err := key.ParseSecretKey(strings.TrimSpace(string(b)))
		if err != nil {
			return key.SecretKey{}, fmt.Errorf("parse key %s: %w", path, err)
		}
		return sk, nil
	case !errors.Is(err, os.ErrNotExist):
		return key.SecretKey{}, fmt.Errorf("read key %s: %w", path, err)
	}
	if dir := filepath.Dir(path); dir != "." {
		// The state directory holds channel secrets too, and is 0700
		// for the same reason this file is 0600.
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return key.SecretKey{}, err
		}
	}
	sk, err := key.GenerateSecretKey()
	if err != nil {
		return key.SecretKey{}, fmt.Errorf("generate key: %w", err)
	}
	// O_EXCL rather than a plain create: two nodes starting on one
	// state directory would otherwise race, and the loser would write
	// its key over the winner's and then run as the winner - which
	// nobody would see until the pins stopped matching.
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return key.SecretKey{}, fmt.Errorf("create key %s: %w", path, err)
	}
	seed := sk.Bytes()
	if _, err := fmt.Fprintf(f, "%s\n", hex.EncodeToString(seed[:])); err != nil {
		f.Close()
		return key.SecretKey{}, fmt.Errorf("write key %s: %w", path, err)
	}
	if err := f.Close(); err != nil {
		return key.SecretKey{}, fmt.Errorf("write key %s: %w", path, err)
	}
	return sk, nil
}
