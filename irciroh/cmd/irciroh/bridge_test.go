package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"regexp"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tmc/go-iroh-experiments/irciroh"
	"github.com/tmc/go-iroh/gossip"
	"github.com/tmc/go-iroh/iroh"
	"github.com/tmc/go-iroh/key"
)

// startBridge binds an iroh endpoint on loopback, wraps it in a bridge, and
// serves IRC on an ephemeral port. It returns the IRC address.
func startBridge(t *testing.T, ctx context.Context) string {
	t.Helper()
	ep, err := iroh.Bind(ctx, iroh.WithBindAddr(netip.AddrPortFrom(netip.IPv6Loopback(), 0)))
	if err != nil {
		t.Fatal(err)
	}
	g := gossip.NewGossip(ep)
	node, err := irciroh.NewNode(ep, g, "")
	if err != nil {
		t.Fatal(err)
	}
	router, err := iroh.NewRouter(ep, map[string]iroh.ProtocolHandler{
		gossip.ALPN:        g.Handler(),
		irciroh.ALPN:       node.Handler(),
		irciroh.InviteALPN: node.InviteHandler(),
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go newBridge(node).Serve(ctx, ln)
	t.Cleanup(func() {
		stop, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		ln.Close()
		node.Close()
		router.Shutdown(stop)
		g.Shutdown(stop)
		ep.Shutdown(stop)
	})
	return ln.Addr().String()
}

// ircClient is a raw IRC connection used to drive a bridge.
type ircClient struct {
	t    *testing.T
	conn net.Conn
	r    *bufio.Reader
}

func dialIRC(t *testing.T, addr string) *ircClient {
	t.Helper()
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	if err := conn.SetDeadline(time.Now().Add(30 * time.Second)); err != nil {
		t.Fatal(err)
	}
	return &ircClient{t: t, conn: conn, r: bufio.NewReader(conn)}
}

// send writes one IRC line.
func (c *ircClient) send(line string) {
	c.t.Helper()
	if _, err := c.conn.Write([]byte(line + "\r\n")); err != nil {
		c.t.Fatalf("send %q: %v", line, err)
	}
}

// expect reads until a line contains every given substring, and returns it.
func (c *ircClient) expect(want ...string) string {
	c.t.Helper()
	for {
		line, err := c.r.ReadString('\n')
		if err != nil {
			c.t.Fatalf("waiting for %v: %v", want, err)
		}
		line = strings.TrimRight(line, "\r\n")
		ok := true
		for _, w := range want {
			if !strings.Contains(line, w) {
				ok = false
				break
			}
		}
		if ok {
			return line
		}
	}
}

// register performs the NICK and USER handshake and waits for 001.
func (c *ircClient) register(nick string) {
	c.t.Helper()
	c.send("CAP LS 302")
	c.expect("CAP * LS :")
	c.send("NICK " + nick)
	c.send("USER " + nick + " 0 * :" + nick)
	c.send("CAP END")
	c.expect(" 001 " + nick)
	c.expect(" 005 "+nick, "CHANTYPES=#")
}

// TestBridge drives two bridges with two raw IRC clients: one channel, a
// ticket join, a message crossing between them, a topic, names, and a
// private message.
func TestBridge(t *testing.T) {
	if testing.Short() {
		t.Skip("network test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	aliceAddr := startBridge(t, ctx)
	bobAddr := startBridge(t, ctx)

	alice := dialIRC(t, aliceAddr)
	alice.register("alice")
	alice.send("PING :hello")
	alice.expect("PONG", "hello")

	alice.send("JOIN #test")
	alice.expect("alice!", "JOIN #test")
	alice.expect(" 353 ", "#test", "alice")
	alice.expect(" 366 ", "#test")

	// An unknown command is rejected, not ignored.
	alice.send("FROBNICATE")
	alice.expect(" 421 ", "FROBNICATE")

	// The TICKET extension yields an invitation bob can join with.
	alice.send("TICKET #test")
	line := alice.expect("NOTICE", irciroh.TicketKind)
	_, params := parseLine(line)
	ticket := params[len(params)-1]
	if _, err := irciroh.ParseTicket(ticket); err != nil {
		t.Fatalf("bridge produced an unparseable ticket %q: %v", ticket, err)
	}

	bob := dialIRC(t, bobAddr)
	bob.register("bob")
	bob.send("JOIN #test " + ticket)
	bob.expect("bob!", "JOIN #test")
	bob.expect(" 366 ", "#test")

	// Alice sees bob arrive, with the nick!id@irciroh prefix.
	joined := alice.expect("JOIN #test", "bob!")
	if !strings.Contains(joined, "@irciroh") {
		t.Fatalf("join line %q has no irciroh host", joined)
	}

	// A message crosses between the two IRC clients.
	bob.send("PRIVMSG #test :hello from bob")
	alice.expect("PRIVMSG #test", "hello from bob", "bob!")

	// So does a notice.
	alice.send("NOTICE #test :and hello from alice")
	bob.expect("NOTICE #test", "and hello from alice", "alice!")

	// A topic set on one side is reported on the other, and by NAMES and
	// TOPIC queries.
	alice.send("TOPIC #test :release planning")
	bob.expect("TOPIC #test", "release planning")
	bob.send("TOPIC #test")
	bob.expect(" 332 ", "#test", "release planning")

	bob.send("NAMES #test")
	names := bob.expect(" 353 ", "#test")
	for _, want := range []string{"alice", "bob"} {
		if !strings.Contains(names, want) {
			t.Fatalf("NAMES %q does not list %s", names, want)
		}
	}
	if strings.Contains(names, "@") {
		t.Fatalf("NAMES %q contains @ on public channel", names)
	}

	bob.send("WHO #test")
	whoLine := bob.expect(" 352 ", "#test")
	if strings.Contains(whoLine, "H@") {
		t.Fatalf("WHO %q contains H@ on public channel", whoLine)
	}
	bob.expect(" 315 ", "#test")

	bob.send("LIST")
	bob.expect(" 322 ", "#test")
	bob.expect(" 323 ")

	bob.send("MODE #test")
	bob.expect(" 324 ", "#test", "+nt")

	// A public channel has no founder, so there is nothing to check a
	// claim of authority against and no operators to make. Every mode
	// that would need one is refused rather than honored on trust.
	bob.send("MODE #test +m")
	bob.expect(" 477 ", "#test")
	bob.send("MODE #test +o alice")
	bob.expect(" 477 ", "#test")
	bob.send("MODE #test +q alice")
	bob.expect(" 472 ")
	bob.send("MODE #test +o")
	bob.expect(" 461 ")
	bob.send("MODE #test +o nobody")
	bob.expect(" 401 ", "nobody")

	// A private message to a nick travels over the direct QUIC stream.
	bob.send("PRIVMSG alice :just between us")
	alice.expect("PRIVMSG alice", "just between us", "bob!")

	// An unknown nick and an unknown channel are refused.
	bob.send("PRIVMSG nobody :hi")
	bob.expect(" 401 ", "nobody")
	bob.send("TOPIC #missing")
	bob.expect(" 403 ", "#missing")

	// Standard IRC diagnostic commands: WHOIS, MOTD, LUSERS, VERSION, TIME.
	bob.send("WHOIS alice")
	bob.expect(" 311 ", "bob", "alice")
	bob.expect(" 319 ", "bob", "alice", "#test")
	bob.expect(" 312 ", "bob", "alice", serverName)
	bob.expect(" 318 ", "bob", "alice")

	bob.send("WHOIS nobody")
	bob.expect(" 401 ", "nobody")

	bob.send("MOTD")
	bob.expect(" 422 ")

	bob.send("LUSERS")
	bob.expect(" 251 ")
	bob.expect(" 254 ")
	bob.expect(" 255 ")

	bob.send("VERSION")
	bob.expect(" 351 ")

	bob.send("TIME")
	bob.expect(" 391 ")

	// USERHOST and ISON
	bob.send("USERHOST alice")
	bob.expect(" 302 ", "alice")
	bob.send("ISON alice nobody")
	bob.expect(" 303 ", "alice")

	// AWAY
	bob.send("AWAY :coding")
	bob.expect(" 306 ")
	bob.send("WHOIS bob")
	bob.expect(" 301 ", "coding")
	bob.send("AWAY")
	bob.expect(" 305 ")

	// INVITE sends channel ticket via QUIC DM
	alice.send("JOIN #other")
	alice.expect("alice!", "JOIN #other")
	alice.send("INVITE bob #other")
	alice.expect(" 341 ", "bob #other")
	bob.expect("PRIVMSG bob", "INVITE #other")

	// Parting is seen on the other side, and QUIT closes the connection.
	bob.send("PART #test")
	alice.expect("PART #test", "bob!")
	bob.send("QUIT :done")
	bob.expect("ERROR")
}

func TestParseLine(t *testing.T) {
	tests := []struct {
		name   string
		in     string
		cmd    string
		params []string
	}{
		{"simple", "NICK alice", "NICK", []string{"alice"}},
		{"lowercase", "nick alice", "NICK", []string{"alice"}},
		{"trailing", "PRIVMSG #go :hello there", "PRIVMSG", []string{"#go", "hello there"}},
		{"prefixed", ":alice!x@y JOIN #go", "JOIN", []string{"#go"}},
		{"no params", "LIST", "LIST", nil},
		{"empty trailing", "QUIT :", "QUIT", []string{""}},
		{"key", "JOIN #go irciroh123", "JOIN", []string{"#go", "irciroh123"}},
		{"empty", "", "", nil},
		{"tags", "@+draft/reply=abc;time=x PRIVMSG #c :hi", "PRIVMSG", []string{"#c", "hi"}},
		{"tags and prefix", "@a=b :alice!x@y TAGMSG #c", "TAGMSG", []string{"#c"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd, params := parseLine(tt.in)
			if cmd != tt.cmd {
				t.Fatalf("command = %q, want %q", cmd, tt.cmd)
			}
			if len(params) != len(tt.params) {
				t.Fatalf("params = %q, want %q", params, tt.params)
			}
			for i := range params {
				if params[i] != tt.params[i] {
					t.Fatalf("params = %q, want %q", params, tt.params)
				}
			}
		})
	}
}

func TestSplitText(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want int
	}{
		{"short", "hello", 1},
		{"exact", strings.Repeat("a", maxText), 1},
		{"words", strings.Repeat("word ", 200), 3},
		{"unbroken", strings.Repeat("a", maxText*2+5), 3},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := splitText(tt.in)
			if len(got) != tt.want {
				t.Fatalf("splitText produced %d pieces, want %d", len(got), tt.want)
			}
			for i, p := range got {
				if len(p) > maxText {
					t.Fatalf("piece %d is %d bytes, over the %d limit", i, len(p), maxText)
				}
			}
		})
	}
}

// TestBridgeSealed drives a sealed channel from two unmodified IRC
// clients: alice founds one with the JOIN key "seal", hands bob the
// ticket the bridge notices back, and the two exchange a message that
// travelled as an MLS ciphertext between the endpoints.
func TestBridgeSealed(t *testing.T) {
	if testing.Short() {
		t.Skip("network test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	aliceAddr, bobAddr := startBridge(t, ctx), startBridge(t, ctx)

	alice := dialIRC(t, aliceAddr)
	alice.register("alice")
	alice.send("JOIN #vault " + sealKey)
	alice.expect("alice!", "JOIN #vault")
	line := alice.expect("NOTICE", irciroh.TicketKind)
	_, params := parseLine(line)
	ticket, err := irciroh.ParseTicket(params[len(params)-1])
	if err != nil {
		t.Fatalf("founding produced an unparseable ticket: %v", err)
	}
	if !ticket.Sealed() {
		t.Fatal("founding produced a ticket for a public channel")
	}

	bob := dialIRC(t, bobAddr)
	bob.register("bob")
	bob.send("JOIN #vault " + ticket.String())
	bob.expect("bob!", "JOIN #vault")

	// Alice sees bob arrive from the commit she made for him, which
	// carries an endpoint and no nick: a sealed channel's membership
	// is the group's roster, and the nick follows in band.
	alice.expect("JOIN #vault")
	alice.expect("NICK", "bob")

	alice.send("PRIVMSG #vault :the eagle has landed")
	bob.expect("PRIVMSG #vault", "the eagle has landed", "alice!")

	// Alice founded #vault, so alice is auto-opped (@) in NAMES, WHO, and WHOIS.
	bob.send("NAMES #vault")
	bob.expect(" 353 ", "#vault", "@alice", "bob")

	bob.send("WHO #vault")
	bob.expect(" 352 ", "#vault", "alice", "H@")
	bob.expect(" 352 ", "#vault", "bob", "H")

	bob.send("WHOIS alice")
	bob.expect(" 319 ", "bob", "alice", "@#vault")
}

// TestBridgeCapNegotiation checks that registration waits for CAP END.
//
// The IRCv3 capability-negotiation specification has a client that has
// started negotiating finish it before the server registers it, so that
// the welcome burst never arrives while the client still believes it is
// choosing capabilities. irciroh negotiates nothing - it has no
// capabilities to offer - but it must still wait to be told the client
// is done.
func TestBridgeCapNegotiation(t *testing.T) {
	if testing.Short() {
		t.Skip("network test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	c := dialIRC(t, startBridge(t, ctx))

	c.send("CAP LS 302")
	c.expect("CAP * LS :")
	c.send("NICK alice")
	c.send("USER alice 0 * :alice")

	// Everything registration needs has been sent, so the only thing
	// keeping the welcome back is the unfinished negotiation.
	if line, ok := c.quiet(250 * time.Millisecond); !ok {
		t.Fatalf("registered before CAP END: %q", line)
	}

	c.send("CAP END")
	c.expect(" 001 alice")

	// LIST after registration asks what is enabled and must not put
	// the client back into negotiation. Nothing is enabled, so the
	// list is empty.
	c.send("CAP LIST")
	c.expect("CAP * LIST :")

	// An unknown subcommand is an error rather than silence.
	c.send("CAP FROB")
	c.expect(" 410 ", "FROB")
}

// quiet reports whether nothing arrives within d, returning the line
// that did arrive when something does.
func (c *ircClient) quiet(d time.Duration) (string, bool) {
	c.t.Helper()
	if err := c.conn.SetReadDeadline(time.Now().Add(d)); err != nil {
		c.t.Fatal(err)
	}
	defer func() {
		if err := c.conn.SetReadDeadline(time.Now().Add(30 * time.Second)); err != nil {
			c.t.Fatal(err)
		}
	}()
	line, err := c.r.ReadString('\n')
	if err != nil {
		return "", true
	}
	return strings.TrimRight(line, "\r\n"), false
}

// TestBridgeRejoinKeepsTheSeal checks that a plain JOIN of a channel
// this node founded returns the sealed channel rather than the public
// one of the same name.
//
// IRC has nowhere to keep a channel key, so a client that reconnects
// sends a bare JOIN for every channel it remembers. A public channel's
// topic is derived from its name alone, so answering that with one
// would move the user from a group only the founder admits onto a topic
// anyone who guesses the name can read, without a word about it.
//
// Positive: after the bare JOIN the founder is still opped in NAMES,
// which only a sealed channel reports.
// Negative control: a bare JOIN of a name never founded joins the
// public channel and reports no operator, so what keeps the seal is the
// founder secret and not the JOIN path.
func TestBridgeRejoinKeepsTheSeal(t *testing.T) {
	if testing.Short() {
		t.Skip("network test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	alice := dialIRC(t, startBridge(t, ctx))
	alice.register("alice")
	alice.send("JOIN #vault " + sealKey)
	alice.expect("alice!", "JOIN #vault")
	alice.expect("NOTICE", irciroh.TicketKind)

	alice.send("JOIN #vault")
	alice.expect(" 353 ", "#vault", "@alice")

	alice.send("JOIN #lobby")
	if line := alice.expect(" 353 ", "#lobby", "alice"); strings.Contains(line, "@alice") {
		t.Fatalf("public #lobby reported an operator: %q", line)
	}
}

// TestDisplayNamesWithoutANick checks that a member whose nick has not
// arrived yet is still named. A sealed channel's member arrives in the
// founder's commit, which carries an endpoint and no nick, so between
// the commit and the nick every line about that member would otherwise
// be missing a parameter rather than naming a stranger.
func TestDisplayNamesWithoutANick(t *testing.T) {
	ka, err := key.GenerateSecretKey()
	if err != nil {
		t.Fatal(err)
	}
	kb, err := key.GenerateSecretKey()
	if err != nil {
		t.Fatal(err)
	}
	a, b := key.EndpointID(ka.Public()), key.EndpointID(kb.Public())
	members := []irciroh.Member{{ID: a}, {ID: b, Nick: "bob"}}
	names := displayNames(members)
	if got, want := names[a], "~"+short(a); got != want {
		t.Errorf("displayNames[a] = %q, want %q", got, want)
	}
	if got, want := names[b], "bob"; got != want {
		t.Errorf("displayNames[b] = %q, want %q", got, want)
	}
	if got, want := prefix(members, members[0]), "~"+short(a)+"!"+short(a)+"@"+serverName; got != want {
		t.Errorf("prefix(a) = %q, want %q", got, want)
	}
}

// TestSecondClientDoesNotRenameTheNode checks that a client registering
// with a different nick is welcomed under the node's own.
//
// One bridge process is one IRC identity, so a nick sent during
// registration is a client saying what it expects to be called rather
// than asking to rename anybody. Honoring it would rename the node for
// every client already attached - and a second client is ordinary now:
// a tool asking for a ticket, or an agent attached to the log.
//
// Positive: the second client's welcome names the first client's nick,
// and the first client is not told of a nick change.
// Negative control: an explicit NICK after registration does rename the
// node, so what is refused is the registration formality and not the
// command.
func TestSecondClientDoesNotRenameTheNode(t *testing.T) {
	if testing.Short() {
		t.Skip("network test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	addr := startBridge(t, ctx)
	alice := dialIRC(t, addr)
	alice.register("alice")

	second := dialIRC(t, addr)
	second.send("NICK tool")
	second.send("USER tool 0 * :tool")
	second.expect(" 001 alice")

	second.send("NICK bob")
	second.expect("NICK", "bob")
	alice.expect("NICK", "bob")
}

// TestResolveRefusesAnAmbiguousNick checks who a nick names when more
// than one member claims it.
//
// A nick is a claim rather than a reservation, and across two channels
// two members can each hold it bare, because each was the only claimant
// where it was seen. Delivering to whichever channel enumerated first
// would send a private message to the wrong person and tell nobody, so
// the answer is a refusal that names the candidates.
//
// Negative control: one claimant on two channels is one claimant, and
// still resolves.
func TestResolveRefusesAnAmbiguousNick(t *testing.T) {
	id := func(t *testing.T) key.EndpointID {
		t.Helper()
		k, err := key.GenerateSecretKey()
		if err != nil {
			t.Fatal(err)
		}
		return key.EndpointID(k.Public())
	}
	a, b, c := id(t), id(t), id(t)
	go1 := []irciroh.Member{{ID: a, Nick: "tmc"}, {ID: c, Nick: "carol"}}
	go2 := []irciroh.Member{{ID: b, Nick: "tmc"}}

	if _, err := resolveIn([][]irciroh.Member{go1, go2}, "tmc"); !errors.Is(err, errAmbiguousNick) {
		t.Errorf("two claimants resolved with err = %v, want %v", err, errAmbiguousNick)
	} else {
		// The refusal is only useful if it says what to send instead.
		for _, want := range []string{short(a), short(b)} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("refusal %q does not name the claimant %s", err, want)
			}
		}
	}
	if m, err := resolveIn([][]irciroh.Member{go1, go2}, "carol"); err != nil || m.ID != c {
		t.Errorf("resolveIn(carol) = %s, %v; want %s", short(m.ID), err, short(c))
	}
	if _, err := resolveIn([][]irciroh.Member{go1, go2}, "nobody"); !errors.Is(err, errNoSuchNick) {
		t.Errorf("resolveIn(nobody) err = %v, want %v", err, errNoSuchNick)
	}
	// One member on two channels is one claimant.
	if m, err := resolveIn([][]irciroh.Member{go1, {{ID: c, Nick: "carol"}}}, "carol"); err != nil || m.ID != c {
		t.Errorf("a member on two channels resolved to %s, %v", short(m.ID), err)
	}
	// rfc1459 folds [] onto {}, so these are one nick to every client
	// and have to be one nick here. Told apart, the bare form would
	// resolve to whichever was written first and the other member
	// would never be reachable at all.
	sq := []irciroh.Member{{ID: a, Nick: "tmc[1]"}, {ID: b, Nick: "tmc{1}"}}
	if _, err := resolveIn([][]irciroh.Member{sq}, "tmc{1}"); !errors.Is(err, errAmbiguousNick) {
		t.Errorf("a folded collision resolved bare: err = %v", err)
	}
	if m, err := resolveIn([][]irciroh.Member{sq}, "tmc{1}~"+short(b)); err != nil || m.ID != b {
		t.Errorf("the disambiguated form resolved to %s, %v; want %s", short(m.ID), err, short(b))
	}
}

// drain reads lines until one contains want, and returns everything
// read before it. It is how a test asks what the server said without
// having to know how much it said.
func (c *ircClient) drain(want string) []string {
	c.t.Helper()
	var got []string
	for {
		line, err := c.r.ReadString('\n')
		if err != nil {
			c.t.Fatalf("waiting for %q: %v", want, err)
		}
		line = strings.TrimRight(line, "\r\n")
		if strings.Contains(line, want) {
			return got
		}
		got = append(got, line)
	}
}

// notices returns the NOTICE lines among lines.
func notices(lines []string) []string {
	var got []string
	for _, line := range lines {
		if strings.Contains(line, " NOTICE ") {
			got = append(got, line)
		}
	}
	return got
}

// TestUnpinnableNickIsAnnounced checks that a client whose nick no peer
// could ever pin is told so once, in words that show it the character
// at fault.
func TestUnpinnableNickIsAnnounced(t *testing.T) {
	for _, tt := range []struct {
		name string
		nick string
		want string // substring of the NOTICE, or "" for no NOTICE
	}{
		{"pinnable", "alice", ""},
		{"punctuation", "al.ice", `'.'`},
		{"space is not even a nick", "alice", ""},
		{"homograph", "\u0430lice", `"\u0430lice"`},
		{"mixed", "\u0430l.ice", `"\u0430l.ice"`},
	} {
		t.Run(tt.name, func(t *testing.T) {
			// A node takes its nick from its first client and
			// keeps it, so each case needs a node of its own.
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			c := dialIRC(t, startBridge(t, ctx))
			c.send("CAP LS 302")
			c.expect("CAP * LS :")
			c.send("NICK " + tt.nick)
			c.send("USER u 0 * :u")
			c.send("CAP END")
			c.expect(" 422 ")
			// The registration burst ends at 422, so a PING
			// afterwards gives the test a line to read up to.
			c.send("PING probe")
			got := notices(c.drain("PONG"))
			if tt.want == "" {
				if len(got) != 0 {
					t.Fatalf("nick %q drew %v, want no notice", tt.nick, got)
				}
				return
			}
			if len(got) != 1 {
				t.Fatalf("nick %q drew %d notices %v, want 1", tt.nick, len(got), got)
			}
			if !strings.Contains(got[0], tt.want) {
				t.Errorf("notice for %q is %q, want it to hold %s", tt.nick, got[0], tt.want)
			}
			if !strings.Contains(got[0], "always carry your key") {
				t.Errorf("notice for %q is %q, want it to say what follows", tt.nick, got[0])
			}
		})
	}
}

// TestUnpinnableNickIsSaidOnce checks that the warning is a warning and
// not a running commentary: changing to the same unpinnable nick again
// says nothing, and changing to a different one says it again.
func TestUnpinnableNickIsSaidOnce(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c := dialIRC(t, startBridge(t, ctx))
	c.send("CAP LS 302")
	c.expect("CAP * LS :")
	c.send("NICK al.ice")
	c.send("USER u 0 * :u")
	c.send("CAP END")
	c.expect(" 422 ")
	c.send("PING one")
	if got := notices(c.drain("PONG")); len(got) != 1 {
		t.Fatalf("registration drew %d notices %v, want 1", len(got), got)
	}

	// The same name again is the same news.
	c.send("NICK al.ice")
	c.send("PING two")
	if got := notices(c.drain("PONG")); len(got) != 0 {
		t.Fatalf("renaming to the same nick drew %v, want nothing", got)
	}

	// A different unpinnable name is news again.
	c.send("NICK al.ic.e")
	c.send("PING three")
	if got := notices(c.drain("PONG")); len(got) != 1 {
		t.Fatalf("renaming drew %d notices %v, want 1", len(got), got)
	}

	// A pinnable name says nothing at all.
	c.send("NICK alice")
	c.send("PING four")
	if got := notices(c.drain("PONG")); len(got) != 0 {
		t.Fatalf("renaming to a pinnable nick drew %v, want nothing", got)
	}
}

// TestErroneousNick checks that a nick the core will not send under is
// answered with 432 and leaves the node's nick as it was, rather than
// telling every client about a rename that did not happen.
func TestErroneousNick(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c := dialIRC(t, startBridge(t, ctx))
	c.register("alice")
	for _, bad := range []string{"\x02bob", ":bad nick"} {
		c.send("NICK " + bad)
		c.send("PING x")
		got := strings.Join(c.drain("PONG"), "\n")
		if !strings.Contains(got, " 432 alice ") || strings.Contains(got, " NICK ") {
			t.Errorf("NICK %q drew %q, want a 432 and no rename", bad, got)
		}
	}
	// The next rename is from alice, so neither refusal took.
	c.send("NICK carol")
	c.expect(":alice!", " NICK :carol")
}

// TestSayWrapsRatherThanTruncates holds the property a delivered
// message needs: the wire carries more text than an IRC line does, so a
// long message arrives as several lines and none of it is dropped. The
// bug this replaces cut the line at 512 bytes and said nothing.
func TestSayWrapsRatherThanTruncates(t *testing.T) {
	who := "alice!abcdef@" + serverName
	const target = "#go"
	text := strings.TrimSpace(strings.Repeat("word ", 400)) // 1999 bytes
	for _, tt := range []struct {
		name string
		text string
		want int
	}{
		{"short", "hello", 1},
		{"long", text, 5},
		{"newlines are their own lines", "one\ntwo", 2},
	} {
		t.Run(tt.name, func(t *testing.T) {
			b, c, out := sayTo(t)
			b.say(key.EndpointID{}, "PRIVMSG", who, target, tt.text)
			flushOut(c)
			lines := strings.Split(strings.TrimSuffix(out.String(), "\r\n"), "\r\n")
			if len(lines) != tt.want {
				t.Fatalf("delivered %d lines, want %d:\n%s", len(lines), tt.want, out)
			}
			var said []string
			for _, line := range lines {
				if len(line)+2 > maxLine {
					t.Errorf("line is %d bytes, over the %d an IRC client reads", len(line)+2, maxLine)
				}
				prefix := ":" + who + " PRIVMSG " + target + " :"
				rest, ok := strings.CutPrefix(line, prefix)
				if !ok {
					t.Fatalf("line %q is not a %s to %s", line, "PRIVMSG", target)
				}
				said = append(said, rest)
			}
			// Every word survives, in order, whatever the wrapping did
			// to the spaces between them.
			if got, want := strings.Fields(strings.Join(said, " ")), strings.Fields(tt.text); !slices.Equal(got, want) {
				t.Errorf("delivered %d words, want %d", len(got), len(want))
			}
		})
	}
}

// TestSayPassesACTCPWhole holds the exception: a CTCP is a frame, and
// half of one is not a shorter CTCP.
func TestSayPassesACTCPWhole(t *testing.T) {
	b, c, out := sayTo(t)
	ctcp := "\x01ACTION " + strings.Repeat("a", 900) + "\x01"
	b.say(key.EndpointID{}, "PRIVMSG", "alice!abcdef@"+serverName, "#go", ctcp)
	flushOut(c)
	if n := strings.Count(out.String(), "\r\n"); n != 1 {
		t.Fatalf("delivered %d lines, want the one frame", n)
	}
	// It is still truncated by send, which is the old behaviour and the
	// right one here: what cannot be cut in half can only be cut short.
	if !strings.HasPrefix(out.String(), ":alice!abcdef@"+serverName+" PRIVMSG #go :\x01ACTION aaa") {
		t.Errorf("delivered %q", out.String())
	}
}

// sayTo returns a bridge with one client on it, and the bytes that
// client is written.
func sayTo(t *testing.T) (*bridge, *client, *strings.Builder) {
	t.Helper()
	b := &bridge{clients: make(map[*client]bool), pumps: make(map[*irciroh.Channel]bool)}
	var out strings.Builder
	c := &client{bridge: b, w: bufio.NewWriter(&out), out: make(chan string, sendQueue)}
	b.clients[c] = true
	return b, c, &out
}

// flushOut writes what has been queued for c, as its writer would.
func flushOut(c *client) {
	for len(c.out) > 0 {
		c.put(<-c.out)
	}
	c.w.Flush()
}

// TestPumpFollowsTheChannelNotTheName holds the property a rejoin needs.
// A part and a rejoin make two channels of one name: the first is shut
// down and its pump is leaving, but it has not necessarily left. Keyed
// on the name, the arriving pump saw the departing one still recorded
// and returned, and then the departing one cleaned up after itself -
// leaving a channel joined, in the roster, and delivering nothing to
// anybody for the life of the process.
func TestPumpFollowsTheChannelNotTheName(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	ep, err := iroh.Bind(ctx, iroh.WithBindAddr(netip.AddrPortFrom(netip.IPv6Loopback(), 0)))
	if err != nil {
		t.Fatal(err)
	}
	g := gossip.NewGossip(ep)
	node, err := irciroh.NewNode(ep, g, "alice")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { node.Close() })
	b := newBridge(node)

	first, err := node.JoinTicket(ctx, irciroh.Ticket{Channel: "#race"})
	if err != nil {
		t.Fatal(err)
	}
	go b.pump(first)
	waitPump(t, b, first, true, "the joined channel is not pumped")

	if err := first.Part(ctx, ""); err != nil {
		t.Fatal(err)
	}
	second, err := node.JoinTicket(ctx, irciroh.Ticket{Channel: "#race"})
	if err != nil {
		t.Fatal(err)
	}
	if first == second {
		t.Fatal("the rejoin returned the channel that was parted")
	}

	// The arriving pump is not turned away by the departing one, which
	// it cannot tell apart by name.
	b.mu.Lock()
	b.pumps[first] = true // as if it had not got to its cleanup yet
	b.mu.Unlock()
	go b.pump(second)
	waitPump(t, b, second, true, "the rejoined channel is not pumped")

	// And a pump that really is departing removes only itself. first
	// is parted, so its loop has ended; delete the stand-in and let
	// the real one clean up with second's entry in place.
	b.mu.Lock()
	delete(b.pumps, first)
	b.mu.Unlock()
	waitPump(t, b, second, true, "the departing pump took the rejoin's entry with it")

	// Joining a channel this node is already on returns that same
	// channel, which is the duplicate the map exists to refuse.
	again, err := node.JoinTicket(ctx, irciroh.Ticket{Channel: "#race"})
	if err != nil {
		t.Fatal(err)
	}
	if again != second {
		t.Fatal("rejoining a channel already joined made a second one")
	}
	b.pump(again) // returns at once rather than pumping twice
	waitPump(t, b, second, true, "the duplicate pump evicted the real one")
}

// waitPump waits for ch's pump entry to be want, and says so if it
// never is.
func waitPump(t *testing.T, b *bridge, ch *irciroh.Channel, want bool, why string) {
	t.Helper()
	for range 100 {
		b.mu.Lock()
		got := b.pumps[ch]
		b.mu.Unlock()
		if got == want {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("%s: pumped(%s %p) = %v, want %v", why, ch.Name(), ch, !want, want)
}

// startNodeBridge builds a bridge the way a real command does - through
// nodeFlags, so the flag, the option and the router registration are the
// ones a user gets rather than a copy of them made for the test - and
// serves IRC on an ephemeral port. Discovery and relays are off: both
// ends are on this machine and the ticket carries the address.
func startNodeBridge(t *testing.T, ctx context.Context, recall bool) string {
	t.Helper()
	n := &nodeFlags{bind: "[::1]:0", state: t.TempDir(), recall: recall}
	node, stop, err := n.open(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(stop)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go newBridge(node).Serve(ctx, ln)
	return ln.Addr().String()
}

// silence fails if a line containing want arrives within d. It is how the
// off case is checked: the claim there is that nothing is replayed, and
// nothing arriving is only evidence if something was waited for.
func (c *ircClient) silence(d time.Duration, want string) {
	c.t.Helper()
	if err := c.conn.SetReadDeadline(time.Now().Add(d)); err != nil {
		c.t.Fatal(err)
	}
	defer c.conn.SetReadDeadline(time.Now().Add(30 * time.Second))
	for {
		line, err := c.r.ReadString('\n')
		if err != nil {
			return // the deadline, which is what is wanted
		}
		if strings.Contains(line, want) {
			c.t.Fatalf("expected no %q, got %q", want, strings.TrimRight(line, "\r\n"))
		}
	}
}

// TestBridgeReplaysWhatWasSaidBeforeTheJoin drives the history wiring end
// to end: -recall on both nodes, a line said before the second one
// existed, and the line arriving after its join.
//
// What it is really checking is how the line arrives. A replay is hearsay
// - this node was handed an envelope, it did not hear the words said - so
// it must not reach a client as speech. Any client that learns the words
// at all must learn them marked.
func TestBridgeReplaysWhatWasSaidBeforeTheJoin(t *testing.T) {
	if testing.Short() {
		t.Skip("network test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	const said = "said before bob arrived"
	alice := dialIRC(t, startNodeBridge(t, ctx, true))
	alice.register("alice")
	alice.send("JOIN #recall")
	alice.expect(" 366 ", "#recall")
	alice.send("PRIVMSG #recall :" + said)

	alice.send("TICKET #recall")
	_, params := parseLine(alice.expect("NOTICE", irciroh.TicketKind))
	ticket := params[len(params)-1]

	bob := dialIRC(t, startNodeBridge(t, ctx, true))
	bob.register("bob")
	bob.send("JOIN #recall " + ticket)
	bob.expect(" 366 ", "#recall")

	// Whatever line carries those words is the one under test: if the
	// replay ever went out as speech this is the line that would say so.
	line := bob.expect(said)
	if strings.Contains(line, "PRIVMSG") {
		t.Errorf("a replayed line reached a client as speech: %q", line)
	}
	for _, want := range []string{"NOTICE", "[replay", "<alice>"} {
		if !strings.Contains(line, want) {
			t.Errorf("replay line %q does not contain %q", line, want)
		}
	}
}

// TestBridgeKeepsNoHistoryWithoutRecall is the control for the test above:
// with -recall=false the same channel replays nothing, so what that test
// measures is the wiring and not something the node would have done
// anyway.
func TestBridgeKeepsNoHistoryWithoutRecall(t *testing.T) {
	if testing.Short() {
		t.Skip("network test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	const said = "said before bob arrived"
	alice := dialIRC(t, startNodeBridge(t, ctx, false))
	alice.register("alice")
	alice.send("JOIN #recall")
	alice.expect(" 366 ", "#recall")
	alice.send("PRIVMSG #recall :" + said)

	alice.send("TICKET #recall")
	_, params := parseLine(alice.expect("NOTICE", irciroh.TicketKind))
	ticket := params[len(params)-1]

	bob := dialIRC(t, startNodeBridge(t, ctx, false))
	bob.register("bob")
	bob.send("JOIN #recall " + ticket)
	bob.expect(" 366 ", "#recall")
	bob.silence(3*time.Second, said)
}

// testNode binds a node on loopback under nick, for a test that plays
// the other end of a conversation without an IRC client of its own.
func testNode(t *testing.T, ctx context.Context, nick string) *irciroh.Node {
	t.Helper()
	ep, err := iroh.Bind(ctx, iroh.WithBindAddr(netip.AddrPortFrom(netip.IPv6Loopback(), 0)))
	if err != nil {
		t.Fatal(err)
	}
	g := gossip.NewGossip(ep)
	node, err := irciroh.NewNode(ep, g, nick)
	if err != nil {
		t.Fatal(err)
	}
	router, err := iroh.NewRouter(ep, map[string]iroh.ProtocolHandler{
		gossip.ALPN:        g.Handler(),
		irciroh.ALPN:       node.Handler(),
		irciroh.InviteALPN: node.InviteHandler(),
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		stop, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		node.Close()
		router.Shutdown(stop)
		g.Shutdown(stop)
		ep.Shutdown(stop)
	})
	return node
}

// serveNode serves IRC for node on an ephemeral port.
func serveNode(t *testing.T, ctx context.Context, node *irciroh.Node) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go newBridge(node).Serve(ctx, ln)
	return ln.Addr().String()
}

// TestBridgeKeepsTheWireClean hands the bridge what a hostile peer can
// get into a core event if it does not run this core: a nick that is a
// whole hostmask with a line break after it, a message with a bare CR,
// a topic with CR, LF and NUL, and a parting reason and a new nick
// that try the same. Every one of them has to arrive as text in a line
// of its own, and no prefix may be one the peer wrote.
func TestBridgeKeepsTheWireClean(t *testing.T) {
	b := newBridge(nil)
	server, conn := net.Pipe()
	t.Cleanup(func() { conn.Close() })
	c := newClient(b, server)
	b.mu.Lock()
	b.clients[c] = true
	b.mu.Unlock()
	lines := make(chan string, 64)
	go func() {
		defer close(lines)
		r := bufio.NewReader(conn)
		for {
			line, err := r.ReadString('\n')
			if err != nil {
				return
			}
			lines <- line
		}
	}()

	evil := irciroh.Member{ID: testKey(t, 1), Nick: "tmc!a3f19c@irciroh\r\n:irciroh NOTICE alice :forged-by-nick"}
	carol := irciroh.Member{ID: testKey(t, 2), Nick: "carol"}
	members := []irciroh.Member{carol, evil}
	now := time.Now()
	for _, ev := range []irciroh.Event{
		{Kind: irciroh.Joined, From: evil, Time: now},
		{Kind: irciroh.Message, From: evil, Text: "hello\r:irciroh 001 alice :forged-by-cr", Time: now},
		{Kind: irciroh.TopicChanged, From: evil, Text: "topic\r\n:root!a3f19c@irciroh PRIVMSG #probe :forged-by-topic\x00nul", Time: now},
		{Kind: irciroh.NickChanged, From: evil, Old: evil.Nick, Text: "x!a3f19c@irciroh\r\n:irciroh NOTICE alice :forged-by-rename", Time: now},
		{Kind: irciroh.Parted, From: evil, Text: "bye\r\n:irciroh NOTICE alice :forged-by-part", Time: now},
		{Kind: irciroh.Message, From: carol, Text: "the end", Time: now},
	} {
		b.relay("#probe", members, ev)
	}

	var raw strings.Builder
	for !strings.Contains(raw.String(), "the end") {
		select {
		case line, ok := <-lines:
			if !ok {
				t.Fatalf("connection closed; read %q", raw.String())
			}
			raw.WriteString(line)
		case <-time.After(10 * time.Second):
			t.Fatalf("timed out; read %q", raw.String())
		}
	}
	// The lines arrive, as text: what is checked below is how.
	for _, want := range []string{"forged-by-cr", "forged-by-topic", "forged-by-part"} {
		if !strings.Contains(raw.String(), want) {
			t.Errorf("never saw %s; read %q", want, raw.String())
		}
	}
	for _, line := range strings.SplitAfter(raw.String(), "\n") {
		if line == "" {
			continue
		}
		body, ok := strings.CutSuffix(line, "\r\n")
		if !ok || strings.ContainsAny(body, "\r\n\x00") {
			t.Errorf("line not ended by its only CRLF: %q", line)
		}
		for _, forged := range []string{":irciroh 001 alice :forged", ":root!", ":irciroh NOTICE alice :forged", ":tmc!a3f19c@irciroh ", ":x!a3f19c@irciroh "} {
			if strings.HasPrefix(body, forged) {
				t.Errorf("a peer wrote a line of its own: %q", body)
			}
		}
		if p, _, _ := strings.Cut(body, " "); strings.HasPrefix(p, ":") && strings.ContainsAny(p, "!@") && !memberPrefix.MatchString(p) {
			t.Errorf("prefix %q is not one nick!user@host", p)
		}
	}
}

// memberPrefix is the shape of the prefix the bridge gives a member.
var memberPrefix = regexp.MustCompile(`^:[^!@:\s]+![0-9a-f]{6}@` + serverName + `$`)

// TestDisplayNick holds the names the bridge will write into a prefix.
func TestDisplayNick(t *testing.T) {
	for _, tt := range []struct{ in, want string }{
		{"alice", "alice"},
		{"tmc!a3f19c@irciroh", "tmc_a3f19c_irciroh"},
		{"a\r\nb", "a__b"},
		{"bob~123456", "bob_123456"},
		{"9lives", "_9lives"},
		{"-dash", "_-dash"},
		{"élan", "_lan"},
		{" ", "_"},
		{strings.Repeat("x", 40), strings.Repeat("x", nickLen)},
	} {
		if got := displayNick(tt.in); got != tt.want {
			t.Errorf("displayNick(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

// TestNobodyIsShownAsTheServer holds that the server's name is the
// server's: a member who claims it, in any case, is shown suffixed.
func TestNobodyIsShownAsTheServer(t *testing.T) {
	k, err := key.GenerateSecretKey()
	if err != nil {
		t.Fatal(err)
	}
	id := key.EndpointID(k.Public())
	m := irciroh.Member{ID: id, Nick: "IRCIROH"}
	want := "IRCIROH~" + short(id)
	if got := displayNames([]irciroh.Member{m})[id]; got != want {
		t.Errorf("displayNames = %q, want %q", got, want)
	}
	if got := prefix(nil, m); !strings.HasPrefix(got, want+"!") {
		t.Errorf("prefix = %q, want it to start %q", got, want+"!")
	}
}

// TestKickRefusesAnAmbiguousNick holds that a kick, which is a ban,
// names one member or nobody: with two bobs in the channel the bare
// name is refused, and the name the channel shows the second one by
// bans that one.
func TestKickRefusesAnAmbiguousNick(t *testing.T) {
	if testing.Short() {
		t.Skip("network test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	alice := dialIRC(t, startBridge(t, ctx))
	alice.register("alice")
	alice.send("JOIN #vault " + sealKey)
	_, params := parseLine(alice.expect("NOTICE", irciroh.TicketKind))
	tk, err := irciroh.ParseTicket(params[len(params)-1])
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if _, err := testNode(t, ctx, "bob").JoinTicket(ctx, tk); err != nil {
			t.Fatal(err)
		}
	}
	suffixed := regexp.MustCompile(`\bbob~[0-9a-f]{6}\b`)
	var second string
	for deadline := time.Now().Add(30 * time.Second); second == ""; {
		alice.send("NAMES #vault")
		line := alice.expect(" 353 ", "#vault")
		if slices.Contains(strings.Fields(line), "bob") {
			second = suffixed.FindString(line)
		}
		if second == "" && time.Now().After(deadline) {
			t.Fatalf("never saw both bobs: %q", line)
		}
		time.Sleep(100 * time.Millisecond)
	}
	alice.send("KICK #vault bob")
	alice.expect(" 407 ", "bob")
	alice.send("KICK #vault " + second)
	alice.expect(" KICK #vault " + second)
}

// TestSlowClientIsDropped holds that a client which stops reading
// costs itself its connection and costs the others nothing.
func TestSlowClientIsDropped(t *testing.T) {
	b := &bridge{clients: make(map[*client]bool), pumps: make(map[*irciroh.Channel]bool)}
	stuckConn, stuckPeer := net.Pipe()
	defer stuckPeer.Close()
	stuck := newClient(b, stuckConn)
	liveConn, livePeer := net.Pipe()
	defer livePeer.Close()
	live := newClient(b, liveConn)
	b.clients[stuck], b.clients[live] = true, true

	// Two queues' worth, in two halves, with a pause between them for
	// the reading client to catch up. The stuck client's writer takes
	// lines off its queue into a bufio.Writer until the pipe blocks it,
	// so it holds a buffer's worth beyond the queue, and only a whole
	// second queue's worth is sure to overflow it. The pause is what
	// keeps the reading client, whose queue is no longer, from
	// overflowing too when the broadcast outruns its reader.
	const n = 2 * sendQueue
	var read atomic.Int64
	got := make(chan int)
	go func() {
		r := bufio.NewReader(livePeer)
		for read.Load() < n {
			if _, err := r.ReadString('\n'); err != nil {
				break
			}
			read.Add(1)
		}
		got <- int(read.Load())
	}()
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := range n {
			if i == sendQueue {
				for read.Load() < sendQueue {
					time.Sleep(time.Millisecond)
				}
			}
			b.broadcast(nil, ":irciroh NOTICE * :line %d", i)
		}
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("a client that does not read stopped the broadcast")
	}
	if count := <-got; count != n {
		t.Errorf("the reading client got %d lines, want %d", count, n)
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.clients[stuck] {
		t.Error("the client that stopped reading is still attached")
	}
}

// TestPrivateMessagesOutlastAStalledCTCPReply holds that a peer which
// asks for VERSION and never acknowledges the answer does not stop the
// private messages behind it.
func TestPrivateMessagesOutlastAStalledCTCPReply(t *testing.T) {
	if testing.Short() {
		t.Skip("network test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	alice := testNode(t, ctx, "alice")
	cl := dialIRC(t, serveNode(t, ctx, alice))
	cl.register("alice")

	// A peer whose private-message handler takes a stream and never
	// answers it.
	ep, err := iroh.Bind(ctx, iroh.WithBindAddr(netip.AddrPortFrom(netip.IPv6Loopback(), 0)))
	if err != nil {
		t.Fatal(err)
	}
	evil, err := irciroh.NewNode(ep, gossip.NewGossip(ep), "evil")
	if err != nil {
		t.Fatal(err)
	}
	stalled := make(chan struct{}, 1)
	router, err := iroh.NewRouter(ep, map[string]iroh.ProtocolHandler{
		irciroh.ALPN: iroh.ProtocolHandlerFunc(func(ctx context.Context, conn *iroh.Conn) error {
			s, err := conn.AcceptStream(ctx)
			if err != nil {
				return err
			}
			s.Read(make([]byte, 1))
			select {
			case stalled <- struct{}{}:
			default:
			}
			<-ctx.Done()
			return nil
		}),
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		stop, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		evil.Close()
		router.Shutdown(stop)
		ep.Shutdown(stop)
	})
	if err := evil.SendPrivate(ctx, alice.ID(), alice.Addr(), "\x01VERSION\x01"); err != nil {
		t.Fatal(err)
	}
	select {
	case <-stalled:
	case <-time.After(10 * time.Second):
		t.Fatal("the VERSION query was not answered at all")
	}
	bob := testNode(t, ctx, "bob")
	if err := bob.SendPrivate(ctx, alice.ID(), alice.Addr(), "hello from bob"); err != nil {
		t.Fatal(err)
	}
	cl.conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	cl.expect("PRIVMSG", "hello from bob")
}

// TestInviteDoesNotNameTheNode holds that asking a bridge for a ticket
// is not registering with it: a node with no nick still has none, and
// the first client to register names it.
func TestInviteDoesNotNameTheNode(t *testing.T) {
	if testing.Short() {
		t.Skip("network test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	addr := startBridge(t, ctx)
	if _, err := ask(addr, "TICKET #nothere", ticketNotice); err == nil {
		t.Fatal("a ticket to a channel the node is not in")
	}
	c := dialIRC(t, addr)
	c.send("NICK gopher")
	c.send("USER gopher 0 * :gopher")
	c.expect(" 001 gopher")
}

// TestTicketNotice holds which line answers TICKET: an untagged notice
// from the server to a nick, holding a ticket and nothing else.
func TestTicketNotice(t *testing.T) {
	tk := irciroh.TicketKind + "abc"
	for _, tt := range []struct {
		line string
		ok   bool
	}{
		{":irciroh NOTICE alice :" + tk, true},
		{":irciroh NOTICE * :" + tk, true},
		{"@irciroh/key=ab :irciroh NOTICE alice :" + tk, false},
		{":irciroh!abcdef@irciroh NOTICE alice :" + tk, false},
		{":irciroh NOTICE #go :" + tk, false},
		{":irciroh NOTICE alice :here is " + tk, false},
		{":irciroh NOTICE alice :" + tk + " and more", false},
		{":mallory NOTICE alice :" + tk, false},
	} {
		got, ok := ticketNotice(tt.line)
		if ok != tt.ok || ok && got != tk {
			t.Errorf("ticketNotice(%q) = %q, %v; want ok %v", tt.line, got, ok, tt.ok)
		}
	}
}

// TestBridgeRefusesWhatIsNotIRC holds the two ways a connection is cut
// before it is read: a line longer than any IRC line, and a first line
// that is an HTTP request.
func TestBridgeRefusesWhatIsNotIRC(t *testing.T) {
	if testing.Short() {
		t.Skip("network test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	addr := startBridge(t, ctx)

	long := dialIRC(t, addr)
	go long.conn.Write([]byte("PRIVMSG #x :" + strings.Repeat("a", maxIn) + "\r\n"))
	long.expect("ERROR", "too long")

	web := dialIRC(t, addr)
	web.send("GET / HTTP/1.1")
	web.send("NICK x")
	web.send("USER x 0 * :x")
	if line, err := web.r.ReadString('\n'); err == nil {
		t.Errorf("an HTTP request was answered: %q", line)
	}
}

// TestTagmsgIsIgnored holds that a client which sends typing
// notifications is not told off for each one.
func TestTagmsgIsIgnored(t *testing.T) {
	if testing.Short() {
		t.Skip("network test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	c := dialIRC(t, startBridge(t, ctx))
	c.register("alice")
	c.send("@+typing=active TAGMSG #go")
	c.send("PING :after")
	for _, line := range c.drain("PONG") {
		if strings.Contains(line, " 421 ") {
			t.Errorf("TAGMSG answered: %q", line)
		}
	}
}

// TestClean holds what may not reach the wire inside a line and what
// must: the line breaks and NUL go, tab, CTCP's framing and the
// formatting codes stay.
func TestClean(t *testing.T) {
	for _, tt := range []struct{ in, want string }{
		{":a TOPIC #c :x\r\n:root PRIVMSG #c :y", ":a TOPIC #c :x:root PRIVMSG #c :y"},
		{":a PRIVMSG #c :hello\r:irciroh 001 alice", ":a PRIVMSG #c :hello:irciroh 001 alice"},
		{"nul\x00here", "nulhere"},
		{"esc\x1b[2J", "esc[2J"},
		{"\x01ACTION waves\x01", "\x01ACTION waves\x01"},
		{"\x02b\x03" + "4c\x0f\x16\x1d\x1e\x1f", "\x02b\x03" + "4c\x0f\x16\x1d\x1e\x1f"},
		{"tab\there", "tab\there"},
		{"bell\x07here", "bellhere"},
	} {
		if got := clean(tt.in); got != tt.want {
			t.Errorf("clean(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

// TestPack holds how NAMES is split: every name once, in order, and no
// line over the room it was given.
func TestPack(t *testing.T) {
	var words []string
	for i := range 200 {
		words = append(words, fmt.Sprintf("nick%03d", i))
	}
	lines := pack(words, 100)
	if len(lines) < 2 {
		t.Fatalf("200 names packed into %d line", len(lines))
	}
	for _, l := range lines {
		if len(l) > 100 {
			t.Errorf("line of %d bytes", len(l))
		}
	}
	if got := strings.Fields(strings.Join(lines, " ")); !slices.Equal(got, words) {
		t.Errorf("packed names differ from the names")
	}
	if got := pack(nil, 100); len(got) != 1 || got[0] != "" {
		t.Errorf("pack(nil) = %q, want one empty line", got)
	}
}

// TestLusersWhileClientsCome counts clients while others connect and
// leave. It fails only under the race detector, which is where it
// matters.
func TestLusersWhileClientsCome(t *testing.T) {
	if testing.Short() {
		t.Skip("network test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	addr := startBridge(t, ctx)
	a := dialIRC(t, addr)
	a.register("alice")
	done := make(chan struct{})
	go func() {
		defer close(done)
		for range 50 {
			if c, err := net.Dial("tcp", addr); err == nil {
				c.Close()
			}
		}
	}()
	for range 50 {
		a.send("LUSERS")
		a.expect(" 255 ")
	}
	<-done
}
