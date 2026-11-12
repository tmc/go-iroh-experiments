package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/tmc/go-iroh-experiments/irciroh"
	"github.com/tmc/go-iroh/key"
	"github.com/tmc/go-iroh/netaddr"
)

// serverName is the server name used in IRC prefixes and numerics.
const serverName = "irciroh"

// maxLine is the longest IRC line the bridge writes, including the
// trailing CRLF. It is RFC 1459's limit.
const maxLine = 512

// maxIn is the longest line the bridge reads. IRCv3 gives a client's
// tags a budget of their own, 8191 bytes, on top of the message's 512.
// A longer line is not a line anybody's client sends, and reading it
// whole would let one connection make the bridge hold whatever it was
// sent.
const maxIn = 8191 + maxLine

// maxText is the longest message text the bridge passes to the core in one
// envelope. Longer text is split.
const maxText = 400

// sendQueue is how many lines a client may fall behind by before it is
// disconnected. Every client is written to on its own goroutine, so one
// that stops reading holds up nobody else; this is what it may hold
// instead of them.
const sendQueue = 4096

// dmTimeout bounds one private message: the dial, the write and the
// acknowledgement. A peer that accepts the stream and never answers
// would otherwise hold whatever goroutine asked for as long as the
// connection lived.
const dmTimeout = 15 * time.Second

// ctcpReplies is how many CTCP answers may be in flight at once. A query
// is not owed an answer, and one that arrives while this many are
// outstanding is not given one.
const ctcpReplies = 4

// capMessageTags is the IRCv3 capability a client asks for to be sent
// message tags. It is the only one the bridge has, and it exists here
// for one tag: the endpoint a message came from.
const capMessageTags = "message-tags"

// A bridge is a local IRC server in front of one irciroh node. Every client
// connected to it shares the node's identity, nick, and channels.
type bridge struct {
	node *irciroh.Node

	once sync.Once     // starts private
	ctcp chan struct{} // CTCP answers in flight

	mu      sync.Mutex
	clients map[*client]bool
	pumps   map[*irciroh.Channel]bool
}

// newBridge returns a bridge serving node.
func newBridge(node *irciroh.Node) *bridge {
	return &bridge{
		node:    node,
		ctcp:    make(chan struct{}, ctcpReplies),
		clients: make(map[*client]bool),
		pumps:   make(map[*irciroh.Channel]bool),
	}
}

// start begins relaying private messages, once per bridge whichever way
// it is served. The node has one private stream and it has to be read
// whether or not a client is attached yet: a node that is not reading
// it is one its peers are told is not listening.
func (b *bridge) start(ctx context.Context) {
	b.once.Do(func() { go b.private(ctx) })
}

// Serve accepts IRC clients on ln until ctx is done or ln is closed.
func (b *bridge) Serve(ctx context.Context, ln net.Listener) error {
	b.start(ctx)
	go func() {
		<-ctx.Done()
		ln.Close()
	}()
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("accept: %w", err)
		}
		b.attach(ctx, conn)
	}
}

// attach serves one client on a connection somebody else established. It
// is how join runs a bridge and a chat in one process: there is no
// listener there, so there is nothing to accept.
func (b *bridge) attach(ctx context.Context, conn net.Conn) {
	b.start(ctx)
	c := newClient(b, conn)
	b.mu.Lock()
	b.clients[c] = true
	b.mu.Unlock()
	go c.serve(ctx)
}

// drop removes a client from the bridge. Its writer sends what is
// already queued for it and then closes the connection.
func (b *bridge) drop(c *client) {
	b.mu.Lock()
	delete(b.clients, c)
	b.mu.Unlock()
	c.quitOnce.Do(func() { close(c.quit) })
}

// broadcast writes one line to every registered client, skipping except.
func (b *bridge) broadcast(except *client, format string, args ...any) {
	b.tagged(except, key.EndpointID{}, format, args...)
}

// tagged is broadcast for a line somebody said, which is the only kind
// that can be attributed. The clients that negotiated message tags are
// told which endpoint it came from; the rest are sent the line they
// would have been sent before there were any tags, byte for byte,
// because the ordinary IRC clients attached to these bridges have to
// go on working and an unasked-for tag is a line they cannot parse.
func (b *bridge) tagged(except *client, from key.EndpointID, format string, args ...any) {
	b.mu.Lock()
	clients := make([]*client, 0, len(b.clients))
	for c := range b.clients {
		if c != except {
			clients = append(clients, c)
		}
	}
	b.mu.Unlock()
	line := fmt.Sprintf(format, args...)
	stamped := line
	if !from.IsZero() {
		// The tag is the whole key rather than the six hex characters
		// the hostmask beside it shows. Those are for a person to
		// read: twenty-four bits is little enough work to grind that
		// anything comparing them is comparing a name somebody chose
		// rather than a key they hold.
		stamped = fmt.Sprintf("@%s=%s %s", wireKeyTag, from, line)
	}
	for _, c := range clients {
		if c.tags.Load() {
			c.send("%s", stamped)
		} else {
			c.send("%s", line)
		}
	}
}

// say relays one message's text to every client as however many IRC
// lines it takes. An envelope carries far more text than an IRC line
// holds, and the two limits belong to different people: the 512 bytes
// are a property of the connection this client happens to be reading
// on, not of what somebody said into the channel. Cutting the text to
// fit and dropping the rest loses the words to keep the limit.
//
// A CTCP goes whole. It is a frame rather than prose, and half of one
// is not a shorter CTCP, it is a line with a stray \x01 in it.
func (b *bridge) say(from key.EndpointID, verb, who, target, text string) {
	// What the line costs before the text: ":who verb target :", plus
	// the CRLF send adds.
	room := maxLine - 2 - (len(who) + len(verb) + len(target) + 5)
	for _, line := range strings.Split(text, "\n") {
		parts := []string{line}
		if room > 0 && !strings.HasPrefix(line, "\x01") {
			parts = splitAt(line, room)
		}
		for _, part := range parts {
			b.tagged(nil, from, ":%s %s %s :%s", who, verb, target, part)
		}
	}
}

// pump relays a channel's events to every client until the channel ends.
//
// One pump per channel, and the key is the channel and not its name.
// The name was a proxy for the channel's identity and it is not one: a
// part and a rejoin make two channels of one name, the first shut down
// with its pump on the way out but not necessarily gone. Keyed on the
// name, the arriving pump found the departing one recorded and
// returned, and then the departing one's own cleanup ran - leaving a
// channel joined, in the roster, and delivering nothing to anybody for
// the life of the process. Keyed on the channel there is nothing to
// alias: a pump records itself and removes itself. Joining a channel
// this node is already on returns the same channel, so this still
// refuses the second pump, which is what the map was for.
func (b *bridge) pump(ch *irciroh.Channel) {
	b.mu.Lock()
	if b.pumps[ch] {
		b.mu.Unlock()
		return
	}
	b.pumps[ch] = true
	b.mu.Unlock()
	defer func() {
		b.mu.Lock()
		delete(b.pumps, ch)
		b.mu.Unlock()
	}()

	for ev, err := range ch.Events() {
		if err != nil {
			continue
		}
		b.relay(ch.Name(), ch.Members(), ev)
	}
}

// relay writes one event from the channel name to every client, as
// the IRC lines it takes. members is the channel's roster as the event
// arrived. Everything in ev is a peer's claim, and a peer need not run
// this code: the nicks are mapped by [displayNick] and the lines
// cleaned by [clean] whatever the core let through.
func (b *bridge) relay(name string, members []irciroh.Member, ev irciroh.Event) {
	who := prefix(members, ev.From)
	switch ev.Kind {
	case irciroh.Joined:
		b.broadcast(nil, ":%s JOIN %s", who, name)
	case irciroh.Parted:
		b.tagged(nil, ev.From.ID, ":%s PART %s :%s", who, name, ev.Text)
	case irciroh.Message:
		b.say(ev.From.ID, "PRIVMSG", who, name, ev.Text)
	case irciroh.Notice:
		b.say(ev.From.ID, "NOTICE", who, name, ev.Text)
	case irciroh.TopicChanged:
		// Tagged, because a topic is somebody's words as much as a
		// message is, and a reader that compares keys should be
		// able to compare this one.
		b.tagged(nil, ev.From.ID, ":%s TOPIC %s :%s", who, name, ev.Text)
	case irciroh.NickChanged:
		// Both names are shown the way the roster shows them, which
		// is before and after the change: the old one is what a
		// client knows the member by, and the new one has to be a
		// name the client can use.
		before, after := withNick(members, ev.From.ID, ev.Old), withNick(members, ev.From.ID, ev.Text)
		now, ok := displayNames(after)[ev.From.ID]
		if !ok {
			now = nickName(irciroh.Member{ID: ev.From.ID, Nick: ev.Text})
		}
		b.broadcast(nil, ":%s NICK :%s", prefix(before, irciroh.Member{ID: ev.From.ID, Nick: ev.Old}), now)
	case irciroh.ModeChanged:
		flag := "-m"
		if ev.Text == "moderated" {
			flag = "+m"
		}
		b.broadcast(nil, ":%s MODE %s %s", who, name, flag)
	case irciroh.RankChanged:
		// IRC has no word for a rank, only for the flags one
		// implies, so a change is sent as the flags it turns on
		// and off. The ladder makes that at most two.
		by, about := prefix(members, ev.By), displayNames(members)[ev.From.ID]
		if about == "" {
			about = nickName(ev.From)
		}
		for _, flag := range rankFlags(ev.Old, ev.Text) {
			b.broadcast(nil, ":%s MODE %s %s %s", by, name, flag, about)
		}
	case irciroh.Replayed:
		// A replayed line is hearsay. This node did not hear it
		// said; a peer handed over the envelope and this node
		// checked the signature, which proves who wrote the
		// words and nothing about whether they were ever
		// delivered here, or in what order, or that anything
		// between them is not missing.
		//
		// So it does not go out as a PRIVMSG from the
		// speaker's prefix. A client cannot tell one of those
		// from a line said in front of it, and the whole worth
		// of the distinction is that a reader can. It comes
		// from the server, carrying who signed it, who served
		// it, when the signer said it was said - and the
		// speech marks of what it was said as, so that a
		// notice replayed does not come back a message.
		marks := "<%s> %s"
		if ev.Was == irciroh.Notice {
			marks = "-%s- %s"
		}
		//
		// The signer's key rides in the tag, as it would on the
		// line itself, so that a reader comparing keys has one to
		// compare: the nick in the text is only what the signer
		// claimed to be called.
		said := fmt.Sprintf(marks, nickName(ev.From), ev.Text)
		b.tagged(nil, ev.From.ID, ":%s NOTICE %s :[replay %s via %s] %s", serverName, name, ev.Time.UTC().Format("15:04:05Z"), short(ev.Via.ID), said)
	case irciroh.Lagged:
		b.broadcast(nil, ":%s NOTICE %s :messages were dropped", serverName, name)
	case irciroh.Split:
		// From the server, not from a member, because the PARTs
		// that came with it already named the members and this is
		// the line that says not to read them that way.
		b.broadcast(nil, ":%s NOTICE %s :%s", serverName, name, ev.Text)
	case irciroh.Refused:
		// One of these is a netsplit healing; a stream of them
		// is somebody working at it.
		if ev.From.ID.IsZero() {
			b.broadcast(nil, ":%s NOTICE %s :refused: %s", serverName, name, ev.Text)
		} else {
			b.broadcast(nil, ":%s NOTICE %s :refused %s: %s", serverName, name, short(ev.From.ID), ev.Text)
		}
	}
}

// private relays inbound private messages to every client, answering
// the CTCP queries addressed to this node itself.
func (b *bridge) private(ctx context.Context) {
	for ev, err := range b.node.Private() {
		if err != nil {
			continue
		}
		if reply, ok := ctcpReply(ev.Text); ok {
			b.answer(ctx, ev.From.ID, reply)
			continue
		}
		b.say(ev.From.ID, "PRIVMSG", b.dmPrefix(ev.From), b.node.Nick(), ev.Text)
	}
}

// ctcpReply returns the answer to a CTCP query this node answers itself,
// and reports whether text is one.
func ctcpReply(text string) (string, bool) {
	if len(text) < 2 || !strings.HasPrefix(text, "\x01") || !strings.HasSuffix(text, "\x01") {
		return "", false
	}
	ctcp := strings.Trim(text, "\x01")
	switch {
	case ctcp == "VERSION":
		return "\x01VERSION irciroh 0.1 (go-iroh p2p)\x01", true
	case ctcp == "PING" || strings.HasPrefix(ctcp, "PING "):
		return "\x01" + ctcp + "\x01", true
	case ctcp == "CLIENTINFO":
		return "\x01CLIENTINFO ACTION CLIENTINFO PING TIME VERSION\x01", true
	case ctcp == "TIME":
		return fmt.Sprintf("\x01TIME %s\x01", time.Now().UTC().Format(time.RFC1123)), true
	}
	return "", false
}

// answer sends a CTCP reply without holding up the loop that reads
// private messages. The reply is a private message of its own, which
// waits for the peer to acknowledge it, and a peer that asks and then
// never acknowledges would otherwise stop every private message behind
// it. A query that arrives while [ctcpReplies] answers are outstanding
// is not answered.
func (b *bridge) answer(ctx context.Context, to key.EndpointID, text string) {
	select {
	case b.ctcp <- struct{}{}:
	default:
		return
	}
	go func() {
		defer func() { <-b.ctcp }()
		ctx, cancel := context.WithTimeout(ctx, dmTimeout)
		defer cancel()
		_ = b.node.SendPrivate(ctx, to, b.node.PeerAddr(to), text)
	}()
}

// dmPrefix returns the prefix a private message is shown from. A
// private message is filed under its sender's name, so the name is
// suffixed with the key whenever somebody else could be filed under it
// too: another member of a channel this node is on, this node itself,
// or the server.
func (b *bridge) dmPrefix(m irciroh.Member) string {
	name := nickName(m)
	folded := irciroh.Fold(name)
	taken := folded == irciroh.Fold(b.node.Nick()) || folded == irciroh.Fold(serverName)
	for _, ch := range b.node.Channels() {
		for _, o := range ch.Members() {
			if o.ID != m.ID && irciroh.Fold(nickName(o)) == folded {
				taken = true
			}
		}
	}
	if taken {
		name = suffixed(name, m.ID)
	}
	return fmt.Sprintf("%s!%s@%s", name, short(m.ID), serverName)
}

// errNoSuchNick and errAmbiguousNick are why resolve found nobody to
// deliver to. They are separate because they call for opposite answers:
// one says try somebody else, the other says say which one you meant.
var (
	errNoSuchNick    = errors.New("no such nick")
	errAmbiguousNick = errors.New("names more than one member")
)

// resolve finds the member a nick names on any joined channel. The nick may
// carry the disambiguating endpoint suffix the bridge adds.
//
// A nick is a claim rather than a reservation, so it can name more than
// one member, and across channels it can do so without either of them
// being shown a suffix - each was the only claimant where it was seen.
// Resolving that to whichever channel enumerated first would send a
// private message to somebody the sender did not mean and tell neither
// of them, so it resolves to nobody and says who the candidates were.
func (b *bridge) resolve(nick string) (irciroh.Member, error) {
	channels := b.node.Channels()
	rosters := make([][]irciroh.Member, 0, len(channels))
	for _, ch := range channels {
		rosters = append(rosters, ch.Members())
	}
	return resolveIn(rosters, nick)
}

// resolveIn is resolve's decision, over the rosters rather than the node,
// because what it has to get right is which of several claimants a name
// names and that is worth testing without a network under it.
func resolveIn(rosters [][]irciroh.Member, nick string) (irciroh.Member, error) {
	want := irciroh.Fold(nick)
	var found []irciroh.Member
	seen := make(map[key.EndpointID]bool)
	for _, members := range rosters {
		names := displayNames(members)
		for _, m := range members {
			if irciroh.Fold(names[m.ID]) != want && irciroh.Fold(nickName(m)) != want {
				continue
			}
			// The same member is on more than one channel, and that is
			// one claimant rather than two.
			if !seen[m.ID] {
				seen[m.ID] = true
				found = append(found, m)
			}
		}
	}
	if len(found) == 0 {
		return irciroh.Member{}, fmt.Errorf("%s: %w", nick, errNoSuchNick)
	}
	if len(found) > 1 {
		who := make([]string, len(found))
		for i, m := range found {
			who[i] = nickName(m) + "[" + short(m.ID) + "]"
		}
		return irciroh.Member{}, fmt.Errorf("%s: %w: %s", nick, errAmbiguousNick, strings.Join(who, " "))
	}
	return found[0], nil
}

// noSuchNick answers a command that named somebody the bridge will not
// deliver to. An ambiguous nick is not 401: 401 says nobody is there,
// and the sender would try again with the same name.
func (c *client) noSuchNick(nick string, err error) {
	if errors.Is(err, errAmbiguousNick) {
		c.numeric(407, "%s :%v; name one of them", nick, err)
		return
	}
	c.numeric(401, "%s :no such nick", nick)
}

// short returns the six hex characters that identify an endpoint in IRC
// user names.
func short(id key.EndpointID) string { return id.String()[:6] }

// displayNames returns the nick the bridge shows for each member. Nicks are
// claims, not reservations, so a member claiming a nick another member
// already claimed is shown with its endpoint prefix appended. The server's
// own name is claimed before anybody, so that no member is shown as the
// server.
func displayNames(members []irciroh.Member) map[key.EndpointID]string {
	claimed := map[string]bool{irciroh.Fold(serverName): true}
	out := make(map[key.EndpointID]string, len(members))
	for _, m := range members {
		nick := nickName(m)
		folded := irciroh.Fold(nick)
		if claimed[folded] {
			out[m.ID] = suffixed(nick, m.ID)
		} else {
			out[m.ID] = nick
		}
		claimed[folded] = true
	}
	return out
}

// nickName returns the name to show for a member with no roster to
// disambiguate it against. A member whose nick this node has not heard
// yet is shown by its endpoint: a sealed channel's member arrives in
// the founder's commit, which carries an endpoint and no nick, and the
// nick follows in band. IRC has no syntax for a name that is not there,
// so an empty one would not be a nameless member but a broken line.
func nickName(m irciroh.Member) string {
	if m.Nick == "" {
		return "~" + short(m.ID)
	}
	return displayNick(m.Nick)
}

// displayNick maps a nick somebody claimed onto one an IRC client can
// parse: RFC 2812's nick characters, starting with a letter or a
// special, and at most [nickLen] of them. Any other character becomes
// an underscore.
//
// The nick is a remote claim and the bridge writes it into prefixes, so
// what it may hold is what a client will read back out of a prefix. A
// nick of "tmc!a3f19c@irciroh" is a whole hostmask, and a client handed
// it with another hostmask after it parses the first one.
//
// The ~ is refused too, because the bridge writes one: it is how two
// members of one name are told apart, and a nick that arrived with one
// could pass for somebody else's disambiguated name.
func displayNick(nick string) string {
	var b strings.Builder
	for _, r := range nick {
		if r == '~' || r > unicode.MaxASCII || !okNameRune(r) {
			r = '_'
		}
		b.WriteRune(r)
	}
	s := b.String()
	if s == "" {
		return "_"
	}
	if c := s[0]; c == '-' || '0' <= c && c <= '9' {
		s = "_" + s
	}
	if len(s) > nickLen {
		s = s[:nickLen]
	}
	return s
}

// suffixed returns name with id's short form appended, as the bridge
// shows a member whose name somebody else also claims. The name is cut
// so that the whole still fits in [nickLen].
func suffixed(name string, id key.EndpointID) string {
	const suffix = len("~abcdef")
	if len(name) > nickLen-suffix {
		name = name[:nickLen-suffix]
	}
	return name + "~" + short(id)
}

// withNick returns a copy of members with id's nick replaced.
func withNick(members []irciroh.Member, id key.EndpointID, nick string) []irciroh.Member {
	out := slices.Clone(members)
	for i := range out {
		if out[i].ID == id {
			out[i].Nick = nick
		}
	}
	return out
}

// prefix returns the IRC prefix nick!id@irciroh for a member.
func prefix(members []irciroh.Member, m irciroh.Member) string {
	name := nickName(m)
	if got, ok := displayNames(members)[m.ID]; ok {
		name = got
	} else {
		folded := irciroh.Fold(name)
		taken := folded == irciroh.Fold(serverName)
		for _, o := range members {
			if o.ID != m.ID && irciroh.Fold(nickName(o)) == folded {
				taken = true
			}
		}
		if taken {
			name = suffixed(name, m.ID)
		}
	}
	return fmt.Sprintf("%s!%s@%s", name, short(m.ID), serverName)
}

// splitText breaks text into pieces that fit in one envelope, mirroring
// IRC's line limit.
func splitText(text string) []string { return splitAt(text, maxText) }

// splitAt breaks text into pieces of at most n bytes, cutting at a
// space where there is one and never in the middle of a rune.
func splitAt(text string, n int) []string {
	if n < 1 {
		n = 1
	}
	if len(text) <= n {
		return []string{text}
	}
	var out []string
	for len(text) > n {
		cut := n
		for cut > 0 && !isBoundary(text[cut]) {
			cut--
		}
		if cut == 0 {
			cut = n
			for cut > 0 && text[cut]&0xc0 == 0x80 {
				cut--
			}
			if cut == 0 {
				cut = n
			}
		}
		out = append(out, strings.TrimRight(text[:cut], " "))
		text = strings.TrimLeft(text[cut:], " ")
	}
	if text != "" {
		out = append(out, text)
	}
	return out
}

func isBoundary(b byte) bool { return b == ' ' }

// A client is one IRC connection to a bridge.
type client struct {
	bridge *bridge
	conn   net.Conn
	w      *bufio.Writer // written only by write

	// out is what is waiting to be written, and quit is closed when
	// the client is dropped. See [client.send] and [client.write].
	out      chan string
	quit     chan struct{}
	quitOnce sync.Once

	user       string
	away       string
	registered bool
	// capping reports that the client has started capability
	// negotiation and has not yet ended it. Registration waits: the
	// IRCv3 capability-negotiation specification has the server hold
	// off on the welcome burst until CAP END, so that a client learns
	// what it negotiated before it is told it is registered.
	capping bool
	// tags reports that the client asked for message tags. It is set
	// while negotiating, on this client's own goroutine, and read by
	// every goroutine that relays a message to it.
	tags atomic.Bool
	// warned is the nick this client has already been told cannot be
	// pinned. Saying it once is a warning; saying it on every NICK is
	// noise. It is only ever touched on this client's own goroutine.
	warned string
}

// newClient returns a client on conn and starts its writer.
func newClient(b *bridge, conn net.Conn) *client {
	c := &client{
		bridge: b,
		conn:   conn,
		w:      bufio.NewWriter(conn),
		out:    make(chan string, sendQueue),
		quit:   make(chan struct{}),
	}
	go c.write()
	return c
}

// send queues one IRC line for the client. It never waits: every
// client is written to on its own goroutine, because a line said in a
// channel is sent to each client in turn from the goroutine that heard
// it, and one client that had stopped reading would otherwise stop the
// line reaching any of the others. A client that falls [sendQueue]
// lines behind is disconnected; there is no ERROR line to tell it so,
// because it is not reading.
func (c *client) send(format string, args ...any) {
	line := clean(fmt.Sprintf(format, args...))
	// The length limit is on the message. IRCv3 gives tags a budget of
	// their own precisely so that adding one cannot cost the text any
	// characters, and truncating a line to make room for a tag would
	// throw away the words to keep the evidence about them.
	tags := ""
	if rest, ok := strings.CutPrefix(line, "@"); ok {
		if block, body, found := strings.Cut(rest, " "); found {
			tags, line = "@"+block+" ", body
		}
	}
	if n := maxLine - 2; len(line) > n {
		for n > 0 && !utf8.RuneStart(line[n]) {
			n--
		}
		line = line[:n]
	}
	select {
	case c.out <- tags + line:
	default:
		c.bridge.drop(c)
		c.conn.Close()
	}
}

// write writes what send queues until the client is dropped, and then
// what was queued before it was, which is most often the ERROR that
// answers a QUIT. That last part is given a second: a client that has
// gone is not waited for.
func (c *client) write() {
	defer c.conn.Close()
	for {
		select {
		case line := <-c.out:
			if c.put(line) != nil {
				return
			}
		case <-c.quit:
			c.conn.SetWriteDeadline(time.Now().Add(time.Second))
			for {
				select {
				case line := <-c.out:
					if c.put(line) != nil {
						return
					}
				default:
					return
				}
			}
		}
	}
}

// put writes one line, flushing once nothing more is waiting.
func (c *client) put(line string) error {
	c.w.WriteString(line)
	c.w.WriteString("\r\n")
	if len(c.out) > 0 {
		return nil
	}
	return c.w.Flush()
}

// clean removes from a line what would end it early or be acted on
// rather than shown: CR, LF and NUL, and every other C0 control except
// tab, \x01, which frames CTCP, and the ones IRC clients read as
// formatting.
//
// It is here, at the one place every line leaves, because nearly
// everything the bridge writes has something from the network in it - a
// topic, a nick, a parting reason, a replayed line - and a CR in any of
// them would let whoever wrote it put a line of their own on the wire,
// from any prefix they liked.
func clean(s string) string {
	return strings.Map(func(r rune) rune {
		if r < ' ' && !strings.ContainsRune(ircFormat, r) {
			return -1
		}
		return r
	}, s)
}

// ircFormat is the C0 controls a line may carry: tab, CTCP's \x01 and
// the formatting codes - bold, color, reset, reverse, italic,
// strikethrough and underline.
const ircFormat = "\t\x01\x02\x03\x0f\x16\x1d\x1e\x1f"

// numeric writes one numeric reply, addressed to the client's nick.
func (c *client) numeric(n int, format string, args ...any) {
	nick := c.bridge.node.Nick()
	if nick == "" {
		nick = "*"
	}
	c.send(":%s %03d %s %s", serverName, n, nick, fmt.Sprintf(format, args...))
}

// notice writes one NOTICE from the server to this client.
func (c *client) notice(format string, args ...any) {
	nick := c.bridge.node.Nick()
	if nick == "" {
		nick = "*"
	}
	c.send(":%s NOTICE %s :%s", serverName, nick, fmt.Sprintf(format, args...))
}

// unpinnable tells a client once that its nick is one no peer can pin,
// so that it is not surprised to find its key beside its name in every
// line it sends.
//
// The question is asked of the name alone. Whether some peer has
// already pinned this name to a different key is not a fact about the
// nick but a fact about that peer, and the bridge has no business
// reading anybody's pins to answer it.
func (c *client) unpinnable(nick string) {
	if nick == "" || nick == c.warned || okName(nick) == nil {
		return
	}
	c.warned = nick
	// A character they can see is worth naming plainly; a character
	// they cannot see is the whole reason the rule exists, and there
	// the escaped form is what shows them what they typed.
	switch r, bad := badNameRune(nick); {
	case bad && r > unicode.MaxASCII:
		c.notice("your nick is %s, which is not the ASCII it looks like; nobody can pin a name they cannot tell apart from another, so your lines will always carry your key", strconv.QuoteToASCII(nick))
	case bad:
		c.notice("a nick holding %q cannot be pinned, so your lines will always carry your key", r)
	default:
		c.notice("a nick longer than %d characters cannot be pinned, so your lines will always carry your key", nickLen)
	}
}

// serve reads and dispatches lines until the client disconnects.
func (c *client) serve(ctx context.Context) {
	defer c.bridge.drop(c)
	r := bufio.NewReaderSize(c.conn, maxIn)
	first := true
	for {
		b, err := r.ReadSlice('\n')
		if errors.Is(err, bufio.ErrBufferFull) {
			c.send("ERROR :line too long")
			return
		}
		if err != nil {
			return
		}
		line := strings.TrimRight(string(b), "\r\n")
		if line == "" {
			continue
		}
		// A connection that opens with an HTTP request is a browser
		// somebody pointed here, or a page that did it for them, and
		// nothing it sends after is IRC.
		if first && httpRequest(line) {
			return
		}
		first = false
		if quit := c.dispatch(ctx, line); quit {
			return
		}
	}
}

// httpRequest reports whether line is the request line of an HTTP
// request.
func httpRequest(line string) bool {
	method, _, _ := strings.Cut(line, " ")
	switch method {
	case "GET", "POST", "PUT", "HEAD", "OPTIONS", "CONNECT", "DELETE", "PATCH":
		return true
	}
	return false
}

// parseLine splits an IRC line into its command and parameters. Leading
// IRCv3 tags are dropped, since no tag a client sends means anything
// here, and so is a leading prefix: the bridge trusts the connection,
// not the claim.
func parseLine(line string) (string, []string) {
	if strings.HasPrefix(line, "@") {
		_, rest, ok := strings.Cut(line, " ")
		if !ok {
			return "", nil
		}
		line = strings.TrimLeft(rest, " ")
	}
	if strings.HasPrefix(line, ":") {
		_, rest, ok := strings.Cut(line, " ")
		if !ok {
			return "", nil
		}
		line = rest
	}
	head, trailing, hasTrailing := strings.Cut(line, " :")
	params := strings.Fields(head)
	if len(params) == 0 {
		return "", nil
	}
	cmd := strings.ToUpper(params[0])
	params = params[1:]
	if hasTrailing {
		params = append(params, trailing)
	}
	return cmd, params
}

// dispatch handles one line and reports whether the client is done.
func (c *client) dispatch(ctx context.Context, line string) bool {
	cmd, params := parseLine(line)
	switch cmd {
	case "":
		return false
	case "QUIT":
		reason := "client quit"
		if len(params) > 0 {
			reason = params[0]
		}
		c.send("ERROR :%s", reason)
		return true
	case "PING":
		token := serverName
		if len(params) > 0 {
			token = params[0]
		}
		c.send(":%s PONG %s :%s", serverName, serverName, token)
		return false
	case "PONG", "TAGMSG":
		// A TAGMSG carries only tags, and there are none here that
		// mean anything.
		return false
	case "TICKET":
		// Before registration too, so that asking for a ticket need
		// not name the node: registering is how a node with no nick
		// is given one, and a tool that only wanted a ticket would
		// have renamed it. It gives nothing registering would not.
		c.ticket(params)
		return false
	case "NICK":
		c.setNick(params)
		return false
	case "USER":
		c.setUser(params)
		return false
	case "CAP":
		c.cap(params)
		return false
	}
	if !c.registered {
		c.numeric(451, ":you have not registered")
		return false
	}
	switch cmd {
	case "JOIN":
		c.join(ctx, params)
	case "PART":
		c.part(ctx, params)
	case "PRIVMSG":
		c.message(ctx, params, false)
	case "NOTICE":
		c.message(ctx, params, true)
	case "TOPIC":
		c.topic(ctx, params)
	case "NAMES":
		c.names(params)
	case "WHO":
		c.who(params)
	case "WHOIS":
		c.whois(params)
	case "USERHOST":
		c.userhost(params)
	case "ISON":
		c.ison(params)
	case "AWAY":
		c.setAway(params)
	case "INVITE":
		c.invite(ctx, params)
	case "LIST":
		c.list()
	case "MODE":
		c.mode(ctx, params)
	case "KICK":
		c.kick(ctx, params)
	case "MOTD":
		c.numeric(422, ":no message of the day")
	case "LUSERS":
		c.lusers()
	case "VERSION":
		c.numeric(351, "irciroh-1 %s :serverless p2p iroh bridge", serverName)
	case "TIME":
		c.numeric(391, "%s :%s", serverName, time.Now().UTC().Format(time.RFC1123))
	default:
		c.numeric(421, "%s :unknown command", cmd)
	}
	return false
}

// cap handles IRCv3 capability negotiation. The bridge has one
// capability to offer, message-tags, and it must also hold
// registration open until the client says it is done.
func (c *client) cap(params []string) {
	if len(params) == 0 {
		c.numeric(410, "CAP :invalid CAP command")
		return
	}
	sub := strings.ToUpper(params[0])
	switch sub {
	case "LS":
		// LS and REQ both start negotiation. LIST does not: it asks
		// what is enabled, which a registered client may do at any
		// time and which says nothing about whether it is still
		// negotiating.
		c.capping = !c.registered
		c.send(":%s CAP * LS :%s", serverName, capMessageTags)
	case "LIST":
		c.send(":%s CAP * LIST :%s", serverName, c.enabled())
	case "REQ":
		c.capping = !c.registered
		requested := ""
		if len(params) > 1 {
			requested = params[1]
		}
		// A request is granted whole or refused whole, which is what
		// the specification asks for and what spares a client having
		// to work out which half of what it asked for it got.
		if c.request(requested) {
			c.send(":%s CAP * ACK :%s", serverName, requested)
		} else {
			c.send(":%s CAP * NAK :%s", serverName, requested)
		}
	case "END":
		c.capping = false
		c.maybeRegister()
	default:
		c.numeric(410, "%s :invalid CAP command", sub)
	}
}

// request applies a CAP REQ, reporting whether every capability named
// in it is one the bridge has. A name prefixed with a minus asks for
// the capability to be turned off again. Nothing is applied unless all
// of it can be.
func (c *client) request(req string) bool {
	names := strings.Fields(req)
	if len(names) == 0 {
		return false
	}
	want := false
	for _, name := range names {
		on := true
		if rest, ok := strings.CutPrefix(name, "-"); ok {
			name, on = rest, false
		}
		if name != capMessageTags {
			return false
		}
		want = on
	}
	c.tags.Store(want)
	return true
}

// enabled lists the capabilities the client has on.
func (c *client) enabled() string {
	if c.tags.Load() {
		return capMessageTags
	}
	return ""
}

// setNick sets or changes the node's nick.
func (c *client) setNick(params []string) {
	if len(params) == 0 || params[0] == "" {
		c.numeric(431, ":no nickname given")
		return
	}
	want := params[0]
	node := c.bridge.node
	old := node.Nick()
	// A nick sent during registration is a client saying what it
	// expects to be called, not asking to rename anybody. One process
	// is one IRC identity, so honoring it would rename the node out
	// from under every client already attached - and the second client
	// is the common case now that a tool asking for a ticket, or an
	// agent attaching to the log, is one. A node started without a
	// nick still takes its first client's.
	if !c.registered && old != "" {
		c.maybeRegister()
		return
	}
	if err := node.SetNick(want); err != nil {
		c.numeric(432, "%s :erroneous nickname", want)
		return
	}
	if c.registered {
		// Before registration the welcome burst says it, once the
		// client is in a state to read it.
		c.unpinnable(want)
	}
	if c.registered && old != want {
		c.bridge.broadcast(nil, ":%s!%s@%s NICK :%s", old, short(node.ID()), serverName, want)
		return
	}
	c.maybeRegister()
}

// setUser records the USER parameters and completes registration.
func (c *client) setUser(params []string) {
	if len(params) < 4 {
		c.numeric(461, "USER :not enough parameters")
		return
	}
	c.user = params[0]
	c.maybeRegister()
}

// maybeRegister sends the welcome burst once NICK and USER have arrived.
func (c *client) maybeRegister() {
	if c.registered || c.capping || c.user == "" || c.bridge.node.Nick() == "" {
		return
	}
	c.registered = true
	node := c.bridge.node
	c.numeric(1, ":welcome to irciroh, %s!%s@%s", node.Nick(), short(node.ID()), serverName)
	c.numeric(2, ":your host is %s, running on endpoint %s", serverName, node.ID())
	c.numeric(3, ":this server keeps no logs and has no operators; what a channel replays on joining is what its peers recall")
	c.numeric(4, "%s irciroh-1 i nt", serverName)
	c.numeric(5, "CHANTYPES=# CHANMODES=,,,mnt PREFIX=(ov)@+ CHANNELLEN=50 NICKLEN=%d TOPICLEN=307 AWAYLEN=200 KICKLEN=255 USERLEN=18 MODES=1 SAFELIST NETWORK=irciroh CASEMAPPING=rfc1459 TARGMAX=PRIVMSG:1,NOTICE:1 :are supported by this server", nickLen)
	c.numeric(422, ":no message of the day")
	c.unpinnable(node.Nick())
	// Any channel the node already has is joined by this client too.
	for _, ch := range node.Channels() {
		c.sendJoin(ch)
	}
}

// sealKey is the JOIN key that founds a sealed channel rather than
// joining one. IRC has no syntax for this, and a key is the only thing
// JOIN carries besides the name.
const sealKey = "seal"

// join joins one or more channels, using an IRC key parameter as an
// irciroh ticket when it is one, or as the sealed-channel sentinel when
// it is [sealKey].
func (c *client) join(ctx context.Context, params []string) {
	if len(params) == 0 {
		c.numeric(461, "JOIN :not enough parameters")
		return
	}
	names := strings.Split(params[0], ",")
	var keys []string
	if len(params) > 1 {
		keys = strings.Split(params[1], ",")
	}
	for i, name := range names {
		var ticket irciroh.Ticket
		if i < len(keys) && keys[i] == sealKey {
			c.found(ctx, name, true)
			continue
		}
		if i < len(keys) && keys[i] != "" && keys[i] != "x" {
			t, err := irciroh.ParseTicket(keys[i])
			if err != nil {
				c.numeric(475, "%s :cannot join channel: %s", name, err)
				continue
			}
			ticket = t
			if !strings.EqualFold(ticket.Channel, name) {
				c.numeric(475, "%s :ticket is for %s", name, ticket.Channel)
				continue
			}
		} else {
			ticket.Channel = name
		}
		ch, err := c.bridge.node.JoinTicket(ctx, ticket)
		if errors.Is(err, irciroh.ErrFounded) {
			// A client that reconnects sends a bare JOIN for every
			// channel it had, with no key, because IRC has nowhere
			// to keep one. Founding again is what the user meant
			// and what the state on disk supports: the same secret
			// is the same channel. The alternative is to answer
			// with a public channel wearing the same name, which
			// is the one outcome nobody would have asked for.
			c.found(ctx, name, false)
			continue
		}
		if errors.Is(err, irciroh.ErrOtherChannel) {
			// The name is taken by a different channel, and IRC
			// gives a client no way to hold two of one name. Say
			// which way out there is, because the client cannot
			// see the difference it is being refused for: both
			// channels are called the same thing.
			c.numeric(475, "%s :cannot join channel: %s; PART %s first", name, err, name)
			continue
		}
		if err != nil {
			c.numeric(403, "%s :%s", name, err)
			continue
		}
		go c.bridge.pump(ch)
		c.bridge.broadcast(c, ":%s JOIN %s", c.self(), ch.Name())
		c.sendJoin(ch)
	}
}

// found founds or re-founds a sealed channel and reports it to the
// client. It sends the ticket only when the client asked to found,
// since a rejoin did not ask for one and the ticket is a secret.
func (c *client) found(ctx context.Context, name string, asked bool) {
	ch, t, err := c.bridge.node.Found(ctx, name, nil)
	if err != nil {
		c.numeric(475, "%s :cannot found channel: %s", name, err)
		return
	}
	go c.bridge.pump(ch)
	c.bridge.broadcast(c, ":%s JOIN %s", c.self(), ch.Name())
	c.sendJoin(ch)
	if asked {
		c.send(":%s NOTICE %s :%s", serverName, c.bridge.node.Nick(), t)
	}
}

// sendJoin tells this client it is on a channel, with its topic and names.
func (c *client) sendJoin(ch *irciroh.Channel) {
	c.send(":%s JOIN %s", c.self(), ch.Name())
	c.sendTopic(ch)
	c.sendNames(ch)
}

// self returns this client's IRC prefix.
func (c *client) self() string {
	node := c.bridge.node
	return fmt.Sprintf("%s!%s@%s", node.Nick(), short(node.ID()), serverName)
}

// sendTopic reports a channel's topic.
func (c *client) sendTopic(ch *irciroh.Channel) {
	text, by, at, ok := ch.Topic()
	if !ok {
		c.numeric(331, "%s :no topic is set", ch.Name())
		return
	}
	c.numeric(332, "%s :%s", ch.Name(), text)
	c.numeric(333, "%s %s %d", ch.Name(), nickName(by), at.Unix())
}

// sendNames lists a channel's members, in as many 353 lines as it
// takes.
func (c *client) sendNames(ch *irciroh.Channel) {
	members := ch.Members()
	names := displayNames(members)
	shown := make([]string, 0, len(members))
	for _, m := range members {
		shown = append(shown, rankPrefix(m.Rank)+names[m.ID])
	}
	nick := c.bridge.node.Nick()
	if nick == "" {
		nick = "*"
	}
	// What the line costs before the names: ":irciroh 353 nick = #c :".
	room := maxLine - 2 - len(fmt.Sprintf(":%s 353 %s = %s :", serverName, nick, ch.Name()))
	for _, group := range pack(shown, room) {
		c.numeric(353, "= %s :%s", ch.Name(), group)
	}
	c.numeric(366, "%s :end of /NAMES list", ch.Name())
}

// pack joins words with spaces into as few lines of at most room bytes
// as it can. There is always at least one line, empty if there are no
// words, and a word longer than room is a line of its own.
func pack(words []string, room int) []string {
	var lines []string
	line := ""
	for _, w := range words {
		if line != "" && len(line)+1+len(w) > room {
			lines = append(lines, line)
			line = ""
		}
		if line != "" {
			line += " "
		}
		line += w
	}
	return append(lines, line)
}

// part leaves one or more channels.
func (c *client) part(ctx context.Context, params []string) {
	if len(params) == 0 {
		c.numeric(461, "PART :not enough parameters")
		return
	}
	for _, name := range strings.Split(params[0], ",") {
		ch, ok := c.bridge.node.Channel(name)
		if !ok {
			c.numeric(403, "%s :no such channel", name)
			continue
		}
		full := ch.Name()
		reason := ""
		if len(params) > 1 {
			reason = params[1]
		}
		if err := ch.Part(ctx, reason); err != nil {
			c.numeric(403, "%s :%s", full, err)
			continue
		}
		c.bridge.broadcast(nil, ":%s PART %s", c.self(), full)
	}
}

// message sends a PRIVMSG or NOTICE to a channel or a nick.
func (c *client) message(ctx context.Context, params []string, notice bool) {
	if len(params) < 2 {
		c.numeric(461, "PRIVMSG :not enough parameters")
		return
	}
	target, text := params[0], params[1]
	verb := "PRIVMSG"
	if notice {
		verb = "NOTICE"
	}
	if strings.HasPrefix(target, "#") {
		ch, ok := c.bridge.node.Channel(target)
		if !ok {
			c.numeric(403, "%s :no such channel", target)
			return
		}
		for _, part := range splitText(text) {
			var err error
			if notice {
				err = ch.Notice(ctx, part)
			} else {
				err = ch.Say(ctx, part)
			}
			if err != nil {
				c.numeric(404, "%s :%s", ch.Name(), err)
				return
			}
			// The other clients on this bridge are shown the line as
			// though it had come over the network, this node's own
			// endpoint and all: they share the identity that said it,
			// and one of them may be a chat whose log would otherwise
			// have every side of the conversation attributed but this.
			c.bridge.tagged(c, c.bridge.node.ID(), ":%s %s %s :%s", c.self(), verb, ch.Name(), part)
		}
		return
	}

	m, err := c.bridge.resolve(target)
	if err != nil {
		c.noSuchNick(target, err)
		return
	}
	addr := c.bridge.node.PeerAddr(m.ID)
	for _, part := range splitText(text) {
		if err := c.sendPrivate(ctx, m.ID, addr, part); err != nil {
			c.numeric(401, "%s :%s", target, err)
			return
		}
		c.bridge.tagged(c, c.bridge.node.ID(), ":%s %s %s :%s", c.self(), verb, target, part)
	}
}

// sendPrivate sends one private message, giving up after [dmTimeout].
// It is called on the client's own goroutine, and a peer that never
// acknowledges would otherwise leave the client unable to say anything
// else for as long as the connection to that peer lasted.
func (c *client) sendPrivate(ctx context.Context, to key.EndpointID, addr netaddr.EndpointAddr, text string) error {
	ctx, cancel := context.WithTimeout(ctx, dmTimeout)
	defer cancel()
	return c.bridge.node.SendPrivate(ctx, to, addr, text)
}

// topic reads or sets a channel topic.
func (c *client) topic(ctx context.Context, params []string) {
	if len(params) == 0 {
		c.numeric(461, "TOPIC :not enough parameters")
		return
	}
	ch, ok := c.bridge.node.Channel(params[0])
	if !ok {
		c.numeric(403, "%s :no such channel", params[0])
		return
	}
	if len(params) == 1 {
		c.sendTopic(ch)
		return
	}
	if err := ch.SetTopic(ctx, params[1]); err != nil {
		c.numeric(404, "%s :%s", ch.Name(), err)
		return
	}
	c.bridge.broadcast(nil, ":%s TOPIC %s :%s", c.self(), ch.Name(), params[1])
}

// names lists members of the named channels, or of every joined channel.
func (c *client) names(params []string) {
	if len(params) == 0 {
		for _, ch := range c.bridge.node.Channels() {
			c.sendNames(ch)
		}
		return
	}
	for _, name := range strings.Split(params[0], ",") {
		ch, ok := c.bridge.node.Channel(name)
		if !ok {
			c.numeric(366, "%s :end of /NAMES list", name)
			continue
		}
		c.sendNames(ch)
	}
}

// who reports the members of a channel.
func (c *client) who(params []string) {
	if len(params) == 0 {
		c.numeric(315, "* :end of /WHO list")
		return
	}
	target := params[0]
	ch, ok := c.bridge.node.Channel(target)
	if !ok {
		c.numeric(315, "%s :end of /WHO list", target)
		return
	}
	members := ch.Members()
	names := displayNames(members)
	for _, m := range members {
		flags := "H" + rankPrefix(m.Rank)
		c.numeric(352, "%s %s %s %s %s %s :0 %s",
			ch.Name(), short(m.ID), serverName, serverName, names[m.ID], flags, m.Nick)
	}
	c.numeric(315, "%s :end of /WHO list", ch.Name())
}

// whois reports user information for a nick.
func (c *client) whois(params []string) {
	if len(params) == 0 {
		c.numeric(431, ":no nickname given")
		return
	}
	target := params[0]
	// First check if target is the local node itself.
	node := c.bridge.node
	if strings.EqualFold(target, node.Nick()) {
		c.numeric(311, "%s %s %s * :%s", node.Nick(), short(node.ID()), serverName, node.Nick())
		var chs []string
		for _, ch := range node.Channels() {
			chs = append(chs, rankPrefix(ch.Rank(node.ID()))+ch.Name())
		}
		if len(chs) > 0 {
			c.numeric(319, "%s :%s", node.Nick(), strings.Join(chs, " "))
		}
		c.numeric(312, "%s %s :serverless p2p iroh bridge", node.Nick(), serverName)
		if c.away != "" {
			c.numeric(301, "%s :%s", node.Nick(), c.away)
		}
		c.numeric(318, "%s :end of /WHOIS list", node.Nick())
		return
	}

	// Otherwise, search across visible channel members.
	m, err := c.bridge.resolve(target)
	if err != nil {
		c.noSuchNick(target, err)
		return
	}
	shownNick := target
	var commonChannels []string
	for _, ch := range node.Channels() {
		for _, mem := range ch.Members() {
			if mem.ID == m.ID {
				commonChannels = append(commonChannels, rankPrefix(mem.Rank)+ch.Name())
				break
			}
		}
	}
	c.numeric(311, "%s %s %s * :%s", shownNick, short(m.ID), serverName, m.Nick)
	if len(commonChannels) > 0 {
		c.numeric(319, "%s :%s", shownNick, strings.Join(commonChannels, " "))
	}
	c.numeric(312, "%s %s :serverless p2p iroh bridge", shownNick, serverName)
	c.numeric(318, "%s :end of /WHOIS list", shownNick)
}

// lusers reports basic user and channel statistics.
func (c *client) lusers() {
	node := c.bridge.node
	channels := node.Channels()
	knownPeers := make(map[key.EndpointID]bool)
	for _, ch := range channels {
		for _, m := range ch.Members() {
			knownPeers[m.ID] = true
		}
	}
	c.numeric(251, ":There are %d users and 0 invisible on 1 servers", len(knownPeers))
	c.numeric(254, "%d :channels formed", len(channels))
	c.bridge.mu.Lock()
	clients := len(c.bridge.clients)
	c.bridge.mu.Unlock()
	c.numeric(255, ":I have %d clients and 0 servers", clients)
}

// list reports the channels this node has joined.
func (c *client) list() {
	for _, ch := range c.bridge.node.Channels() {
		text, _, _, _ := ch.Topic()
		c.numeric(322, "%s %d :%s", ch.Name(), len(ch.Members()), text)
	}
	c.numeric(323, ":end of /LIST")
}

// rankPrefix returns the IRC nick prefix for a rank: the "@" and "+" that
// ISUPPORT's PREFIX=(ov) names.
func rankPrefix(r irciroh.Rank) string {
	switch r {
	case irciroh.Operator:
		return "@"
	case irciroh.Voiced:
		return "+"
	}
	return ""
}

// rankFlags returns the IRC mode changes that carry a member from the rank
// named old to the one named now. Ranks are a ladder and IRC's o and v are
// independent flags, so losing an op means gaining a voice.
func rankFlags(old, now string) []string {
	var flags []string
	was, is := rankPrefix(parseRankName(old)), rankPrefix(parseRankName(now))
	if was == "@" && is != "@" {
		flags = append(flags, "-o")
	}
	if was == "+" && is == "" {
		flags = append(flags, "-v")
	}
	if is == "@" && was != "@" {
		flags = append(flags, "+o")
	}
	if is == "+" && was == "" {
		flags = append(flags, "+v")
	}
	return flags
}

// parseRankName maps a rank's name back to the rank.
func parseRankName(s string) irciroh.Rank {
	switch s {
	case irciroh.Voiced.String():
		return irciroh.Voiced
	case irciroh.Operator.String():
		return irciroh.Operator
	}
	return irciroh.Ordinary
}

// mode reports and sets channel modes. The channel modes that mean
// anything here are +m, +o and +v; +nt is fixed and reported for the
// clients that expect to see it.
func (c *client) mode(ctx context.Context, params []string) {
	if len(params) == 0 {
		c.numeric(461, "MODE :not enough parameters")
		return
	}
	if !strings.HasPrefix(params[0], "#") {
		c.numeric(221, "+i")
		return
	}
	ch, ok := c.bridge.node.Channel(params[0])
	if !ok {
		c.numeric(403, "%s :no such channel", params[0])
		return
	}
	if len(params) == 1 {
		flags := "+nt"
		if ch.Moderated() {
			flags = "+mnt"
		}
		c.numeric(324, "%s %s", ch.Name(), flags)
		return
	}

	spec := params[1]
	if len(spec) != 2 || (spec[0] != '+' && spec[0] != '-') {
		c.numeric(472, "%s :is unknown mode char to me", spec)
		return
	}
	set, letter := spec[0] == '+', spec[1]
	if letter == 'm' {
		if err := ch.Moderate(ctx, set); err != nil {
			c.modeError(ch, err)
			return
		}
		c.bridge.broadcast(nil, ":%s MODE %s %s", c.me(ch), ch.Name(), spec)
		return
	}
	if letter != 'o' && letter != 'v' {
		c.numeric(472, "%c :is unknown mode char to me", letter)
		return
	}
	if len(params) < 3 {
		c.numeric(461, "MODE :not enough parameters")
		return
	}
	m, err := c.bridge.resolve(params[2])
	if err != nil {
		c.noSuchNick(params[2], err)
		return
	}
	// The ranks are a ladder, so a mode letter names the rung it moves
	// the member to rather than a flag to toggle: -o leaves the voice a
	// deposed operator would keep on IRC.
	want := irciroh.Ordinary
	switch {
	case set && letter == 'o':
		want = irciroh.Operator
	case set && letter == 'v':
		want = irciroh.Voiced
	case !set && letter == 'o':
		want = irciroh.Voiced
	}
	if err := ch.Grant(ctx, m.ID, want); err != nil {
		c.modeError(ch, err)
		return
	}
	about, ok := displayNames(ch.Members())[m.ID]
	if !ok {
		about = nickName(m)
	}
	c.bridge.broadcast(nil, ":%s MODE %s %s %s", c.me(ch), ch.Name(), spec, about)
}

// me returns the local node's IRC prefix as the channel's members see it.
func (c *client) me(ch *irciroh.Channel) string {
	node := c.bridge.node
	return prefix(ch.Members(), irciroh.Member{ID: node.ID(), Nick: node.Nick()})
}

// modeError reports a refused mode change in the numeric a client expects.
func (c *client) modeError(ch *irciroh.Channel, err error) {
	switch {
	case errors.Is(err, irciroh.ErrNotSealed):
		c.numeric(477, "%s :channel has no operators; it is public", ch.Name())
	case errors.Is(err, irciroh.ErrFounderRank):
		c.numeric(482, "%s :the founder's standing is not yours or anyone's to grant", ch.Name())
	case errors.Is(err, irciroh.ErrNotFounder):
		// An operator is refused this too, so saying it needs an
		// operator would be telling it what it already is. Only the
		// founder commits, and Operator is the rank a commit backs.
		c.numeric(482, "%s :only the founder of this channel can do that", ch.Name())
	case errors.Is(err, irciroh.ErrNotOperator):
		c.numeric(482, "%s :you are not a channel operator", ch.Name())
	case errors.Is(err, irciroh.ErrNotMember):
		c.numeric(441, "%s :they are not on that channel", ch.Name())
	default:
		c.numeric(400, "MODE :%s", err)
	}
}

// kick removes a member from a sealed channel and refuses it
// readmission. Only the founder can kick, because only the founder
// commits.
//
// Unlike RFC 1459's KICK this outlives the moment: a member removed for
// going quiet may rejoin with the invite secret it already holds, and a
// kicked one may not. It does not reach the operator behind the
// endpoint, who can mint another one; an admission policy is what does
// that.
func (c *client) kick(ctx context.Context, params []string) {
	if len(params) < 2 {
		c.numeric(461, "KICK :not enough parameters")
		return
	}
	ch, ok := c.bridge.node.Channel(params[0])
	if !ok {
		c.numeric(403, "%s :no such channel", params[0])
		return
	}
	// Resolved the way every other command resolves a nick, against
	// the names the channel is shown: a kick is a ban, and one that
	// took whichever bob came first would ban somebody nobody named.
	members := ch.Members()
	m, err := resolveIn([][]irciroh.Member{members}, params[1])
	if errors.Is(err, errNoSuchNick) {
		c.numeric(441, "%s %s :they are not on that channel", params[1], ch.Name())
		return
	}
	if err != nil {
		c.noSuchNick(params[1], err)
		return
	}
	if err := ch.Kick(ctx, m.ID); err != nil {
		c.numeric(482, "%s :%s", ch.Name(), err)
		return
	}
	reason := params[1]
	if len(params) > 2 {
		reason = params[2]
	}
	c.bridge.broadcast(nil, ":%s KICK %s %s :%s", c.self(), ch.Name(), displayNames(members)[m.ID], reason)
}

// ticket replies with an invitation to a joined channel. It is an
// extension, not an RFC 1459 command; the irciroh invite subcommand uses
// it.
func (c *client) ticket(params []string) {
	if len(params) == 0 {
		c.numeric(461, "TICKET :not enough parameters")
		return
	}
	t, err := c.bridge.node.Ticket(params[0])
	if err != nil {
		c.numeric(403, "%s :%s", params[0], err)
		return
	}
	c.notice("%s", t)
}

// userhost replies with host information for up to 5 nicknames (RFC 2812).
func (c *client) userhost(params []string) {
	if len(params) == 0 {
		c.numeric(461, "USERHOST :not enough parameters")
		return
	}
	var replies []string
	node := c.bridge.node
	limit := len(params)
	if limit > 5 {
		limit = 5
	}
	for _, nick := range params[:limit] {
		if strings.EqualFold(nick, node.Nick()) {
			oper := ""
			away := "+"
			if c.away != "" {
				away = "-"
			}
			replies = append(replies, fmt.Sprintf("%s%s=%s%s@%s", node.Nick(), oper, away, short(node.ID()), serverName))
			continue
		}
		if m, err := c.bridge.resolve(nick); err == nil {
			replies = append(replies, fmt.Sprintf("%s=+%s@%s", nick, short(m.ID), serverName))
		}
	}
	c.numeric(302, ":%s", strings.Join(replies, " "))
}

// ison reports which of the queried nicknames are online (RFC 2812).
func (c *client) ison(params []string) {
	if len(params) == 0 {
		c.numeric(461, "ISON :not enough parameters")
		return
	}
	node := c.bridge.node
	var online []string
	for _, param := range params {
		for _, nick := range strings.Fields(param) {
			if strings.EqualFold(nick, node.Nick()) {
				online = append(online, node.Nick())
				continue
			}
			if _, err := c.bridge.resolve(nick); err == nil {
				online = append(online, nick)
			}
		}
	}
	c.numeric(303, ":%s", strings.Join(online, " "))
}

// setAway sets or removes the client's away message (RFC 2812).
func (c *client) setAway(params []string) {
	if len(params) == 0 || params[0] == "" {
		c.away = ""
		c.numeric(305, ":You are no longer marked as being away")
		return
	}
	c.away = params[0]
	c.numeric(306, ":You have been marked as being away")
}

// invite invites a user to a channel (RFC 2812) by creating a ticket
// and sending it to the recipient via an encrypted QUIC DM.
func (c *client) invite(ctx context.Context, params []string) {
	if len(params) < 2 {
		c.numeric(461, "INVITE :not enough parameters")
		return
	}
	nick, channel := params[0], params[1]
	ch, ok := c.bridge.node.Channel(channel)
	if !ok {
		c.numeric(403, "%s :no such channel", channel)
		return
	}
	m, err := c.bridge.resolve(nick)
	if err != nil {
		c.noSuchNick(nick, err)
		return
	}
	// Check if already on channel.
	for _, member := range ch.Members() {
		if member.ID == m.ID {
			c.numeric(443, "%s %s :is already on channel", nick, channel)
			return
		}
	}
	ticket, err := c.bridge.node.Ticket(channel)
	if err != nil {
		c.numeric(403, "%s :cannot create invite ticket: %s", channel, err)
		return
	}
	addr := c.bridge.node.PeerAddr(m.ID)
	inviteMsg := fmt.Sprintf("INVITE %s :%s (use /join %s %s)", channel, ticket, channel, ticket)
	if err := c.sendPrivate(ctx, m.ID, addr, inviteMsg); err != nil {
		c.numeric(401, "%s :failed to send invite: %s", nick, err)
		return
	}
	c.numeric(341, "%s %s", nick, channel)
}

// ask sends one line to a bridge over IRC, without registering, and
// returns the first reply line matching want. It is how the invite
// subcommand talks to a running bridge. Registering would send a NICK,
// and a NICK is how a bridge whose node has no name yet is given one.
func ask(addr, line string, want func(string) (string, bool)) (string, error) {
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		return "", fmt.Errorf("dial %s: %w", addr, err)
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		return "", err
	}
	fmt.Fprintf(conn, "%s\r\n", line)
	r := bufio.NewReaderSize(conn, maxLine)
	for {
		got, err := r.ReadString('\n')
		if err != nil {
			return "", fmt.Errorf("read reply: %w", err)
		}
		got = strings.TrimRight(got, "\r\n")
		if s, ok := want(got); ok {
			return s, nil
		}
		if _, params := parseLine(got); len(params) > 0 && strings.Contains(got, " 403 ") {
			return "", errors.New(params[len(params)-1])
		}
	}
}

// logKeyTag and wireKeyTag name the endpoint tag in the two places it
// is written. Both sit in an IRCv3 tag block and both are read by the
// same parser, so a second tag - who an account belongs to, whether a
// line was wrapped - can be added to either without the format changing
// shape again.
//
// They differ because only one of the two is IRC. IRCv3 keeps
// unprefixed tag names for its own registry, so a name invented here
// has to carry the vendor that invented it or it is squatting a name
// somebody else may define; the log is this program's own file, read by
// eye as often as by program, and pays a prefix on every line for
// nothing.
const (
	logKeyTag  = "k"
	wireKeyTag = serverName + "/key"
)
