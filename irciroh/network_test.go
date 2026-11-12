package irciroh

import (
	"context"
	"errors"
	"maps"
	"net/netip"
	"os"
	"slices"
	"testing"
	"time"

	"github.com/tmc/go-iroh/gossip"
	"github.com/tmc/go-iroh/iroh"
	"github.com/tmc/go-iroh/key"
	"github.com/tmc/go-iroh/netaddr"
)

// TestMain speeds the presence protocol up for the whole package.
//
// It is done once, before any node exists, rather than per test: a node
// reads these from its own goroutines for as long as it lives, and a
// test that restored them on the way out would be writing while another
// test's node was still reading.
func TestMain(m *testing.M) {
	presenceInterval, presenceTimeout, presenceSweep = 200*time.Millisecond, 2*time.Second, 100*time.Millisecond
	os.Exit(m.Run())
}

// newTestNode returns one in-process node on IPv6 loopback with gossip and
// the private-message handler registered.
func newTestNode(t *testing.T, ctx context.Context, nick string) *Node {
	t.Helper()
	return newTestNodeAt(t, ctx, nick, t.TempDir(), nil)
}

// newTestNodeAt is newTestNode with an explicit state directory and, for
// a node that has to come back as itself, an explicit endpoint key.
func newTestNodeAt(t *testing.T, ctx context.Context, nick, dir string, sk *key.SecretKey) *Node {
	t.Helper()
	opts := []iroh.Option{iroh.WithBindAddr(netip.AddrPortFrom(netip.IPv6Loopback(), 0))}
	if sk != nil {
		opts = append(opts, iroh.WithSecretKey(*sk))
	}
	ep, err := iroh.Bind(ctx, opts...)
	if err != nil {
		t.Fatal(err)
	}
	g := gossip.NewGossip(ep)
	n, err := NewNode(ep, g, nick, WithStateDir(dir))
	if err != nil {
		t.Fatal(err)
	}
	router, err := iroh.NewRouter(ep, map[string]iroh.ProtocolHandler{
		gossip.ALPN: g.Handler(),
		ALPN:        n.Handler(),
		InviteALPN:  n.InviteHandler(),
	}, nil)
	if err != nil {
		_ = ep.Shutdown(ctx)
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = n.Close()
		_ = router.Shutdown(ctx)
		g.Shutdown(ctx)
		_ = ep.Shutdown(ctx)
	})
	return n
}

// events drains a channel's event stream into a buffered Go channel so a
// test can wait on individual events.
func events(t *testing.T, c *Channel) <-chan Event {
	t.Helper()
	out := make(chan Event, 64)
	go func() {
		defer close(out)
		for ev, err := range c.Events() {
			if err != nil {
				continue
			}
			out <- ev
		}
	}()
	return out
}

// await waits for the first event matching want.
func await(t *testing.T, ctx context.Context, in <-chan Event, want func(Event) bool, what string) Event {
	t.Helper()
	for {
		select {
		case ev, ok := <-in:
			if !ok {
				t.Fatalf("event stream ended waiting for %s", what)
			}
			if want(ev) {
				return ev
			}
		case <-ctx.Done():
			t.Fatalf("timed out waiting for %s", what)
		}
	}
}

func ofKind(k EventKind) func(Event) bool {
	return func(ev Event) bool { return ev.Kind == k }
}

// TestNetworkChat runs the whole chat protocol over two real loopback
// endpoints: a ticket join, presence, a channel message, a topic, a nick
// change, a private message, and an explicit part.
func TestNetworkChat(t *testing.T) {
	if testing.Short() {
		t.Skip("network test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	alice := newTestNode(t, ctx, "alice")
	bob := newTestNode(t, ctx, "bob")

	ac, err := alice.Join(ctx, "#Test", nil)
	if err != nil {
		t.Fatal(err)
	}
	ticket, err := alice.Ticket("#test")
	if err != nil {
		t.Fatal(err)
	}
	if ticket.Channel != "#test" {
		t.Fatalf("ticket channel = %q, want %q", ticket.Channel, "#test")
	}
	parsed, err := ParseTicket(ticket.String())
	if err != nil {
		t.Fatal(err)
	}
	bc, err := bob.JoinTicket(ctx, parsed)
	if err != nil {
		t.Fatal(err)
	}
	aliceEvents, bobEvents := events(t, ac), events(t, bc)

	// Each side sees the other join.
	ev := await(t, ctx, aliceEvents, ofKind(Joined), "alice to see bob join")
	if ev.From.Nick != "bob" || ev.From.ID != bob.ID() {
		t.Fatalf("alice saw join from %q %v", ev.From.Nick, ev.From.ID)
	}
	await(t, ctx, bobEvents, ofKind(Joined), "bob to see alice join")

	if got := len(ac.Members()); got != 2 {
		t.Fatalf("alice sees %d members, want 2", got)
	}
	if m := ac.Members()[0]; m.ID != alice.ID() {
		t.Fatalf("first member is %v, want the local node", m.ID)
	}

	// A channel message crosses.
	if err := ac.Say(ctx, "hello, #test"); err != nil {
		t.Fatal(err)
	}
	ev = await(t, ctx, bobEvents, ofKind(Message), "bob to receive alice's message")
	if ev.Text != "hello, #test" || ev.From.Nick != "alice" {
		t.Fatalf("bob received %q from %q", ev.Text, ev.From.Nick)
	}

	// A notice crosses too, and is distinguished from a message.
	if err := bc.Notice(ctx, "brb"); err != nil {
		t.Fatal(err)
	}
	if ev := await(t, ctx, aliceEvents, ofKind(Notice), "alice to receive bob's notice"); ev.Text != "brb" {
		t.Fatalf("alice received notice %q", ev.Text)
	}

	// A topic set on one side is read on the other.
	if err := ac.SetTopic(ctx, "release planning"); err != nil {
		t.Fatal(err)
	}
	ev = await(t, ctx, bobEvents, ofKind(TopicChanged), "bob to see the topic")
	if ev.Text != "release planning" {
		t.Fatalf("bob saw topic %q", ev.Text)
	}
	text, by, _, ok := bc.Topic()
	if !ok || text != "release planning" || by.ID != alice.ID() {
		t.Fatalf("bob's topic = %q by %v (ok=%v)", text, by.ID, ok)
	}

	// A nick change propagates and updates the member table.
	if err := bob.SetNick("robert"); err != nil {
		t.Fatal(err)
	}
	ev = await(t, ctx, aliceEvents, ofKind(NickChanged), "alice to see bob's nick change")
	if ev.Text != "robert" || ev.Old != "bob" {
		t.Fatalf("alice saw nick change %q -> %q", ev.Old, ev.Text)
	}
	var found bool
	for _, m := range ac.Members() {
		if m.ID == bob.ID() {
			found = m.Nick == "robert"
		}
	}
	if !found {
		t.Fatal("alice's member table still shows the old nick")
	}

	// A private message is delivered and acknowledged.
	private := make(chan Event, 4)
	go func() {
		for ev, err := range alice.Private() {
			if err == nil {
				private <- ev
			}
		}
	}()
	addr := bob.PeerAddr(alice.ID())
	if err := bob.SendPrivate(ctx, alice.ID(), addr, "just between us"); err != nil {
		t.Fatal(err)
	}
	select {
	case ev := <-private:
		if ev.Text != "just between us" || ev.From.ID != bob.ID() || ev.From.Nick != "robert" {
			t.Fatalf("alice received private %q from %q %v", ev.Text, ev.From.Nick, ev.From.ID)
		}
	case <-ctx.Done():
		t.Fatal("timed out waiting for the private message")
	}

	// Parting is explicit and immediate, and says why. A reason
	// that would be dropped is refused before anything is left.
	if err := bc.Part(ctx, "back\r\nsoon"); !errors.Is(err, ErrControl) {
		t.Fatalf("part with CRLF in the reason = %v, want %v", err, ErrControl)
	}
	if err := bc.Part(ctx, "back soon"); err != nil {
		t.Fatal(err)
	}
	ev = await(t, ctx, aliceEvents, ofKind(Parted), "alice to see bob part")
	if ev.From.ID != bob.ID() || ev.Text != "back soon" {
		t.Fatalf("alice saw a part from %v saying %q", ev.From.ID, ev.Text)
	}
	if got := len(ac.Members()); got != 1 {
		t.Fatalf("alice sees %d members after the part, want 1", got)
	}
	if _, ok := bob.Channel("#test"); ok {
		t.Fatal("bob still lists #test after parting")
	}
}

// TestNetworkPresenceTimeout checks that a member that stops sending
// presence is dropped, and that a joiner learns the channel topic from a
// presence ping rather than a request and reply.
func TestNetworkPresenceTimeout(t *testing.T) {
	if testing.Short() {
		t.Skip("network test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	alice := newTestNode(t, ctx, "alice")
	bob := newTestNode(t, ctx, "bob")

	ac, err := alice.Join(ctx, "#test", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := ac.SetTopic(ctx, "set before bob arrived"); err != nil {
		t.Fatal(err)
	}
	ticket, err := alice.Ticket("#test")
	if err != nil {
		t.Fatal(err)
	}
	bc, err := bob.JoinTicket(ctx, ticket)
	if err != nil {
		t.Fatal(err)
	}
	bobEvents := events(t, bc)

	// Bob missed the topic envelope, so he learns it from a ping.
	ev := await(t, ctx, bobEvents, ofKind(TopicChanged), "bob to learn the topic from presence")
	if ev.Text != "set before bob arrived" {
		t.Fatalf("bob learned topic %q", ev.Text)
	}

	// Silencing alice's presence expires her from bob's member table.
	aliceEvents := events(t, ac)
	await(t, ctx, aliceEvents, ofKind(Joined), "alice to see bob join")
	alice.cancel()
	ev = await(t, ctx, bobEvents, ofKind(Parted), "bob to time alice out")
	if ev.Text != "timeout" || ev.From.ID != alice.ID() {
		t.Fatalf("bob saw part %q from %v", ev.Text, ev.From.ID)
	}
	if got := len(bc.Members()); got != 1 {
		t.Fatalf("bob sees %d members, want 1", got)
	}
}

// TestPeerAddrFallsBackToTheID checks what a node offers for a peer it
// has no path to. Most members of a channel are heard only through
// gossip, so that is the ordinary case rather than the broken one, and an
// address holding nothing but the id is what the endpoint's address
// lookup resolves. Refusing to produce one turned a message to a member
// sitting in NAMES into "no route to that peer".
func TestPeerAddrFallsBackToTheID(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	alice := newTestNode(t, ctx, "alice")
	sk, err := key.GenerateSecretKey()
	if err != nil {
		t.Fatal(err)
	}
	stranger := sk.Public().EndpointID()

	addr := alice.PeerAddr(stranger)
	if addr.ID != stranger {
		t.Errorf("address is for %v, want %v", addr.ID, stranger)
	}
	if got := len(addr.Addrs()); got != 0 {
		t.Errorf("invented %d paths to a peer never heard from", got)
	}
}

// TestJoinAfterClose checks that a closed node creates no channels.
func TestJoinAfterClose(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	n := newTestNode(t, ctx, "alice")
	if err := n.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := n.Join(ctx, "#late", nil); !errors.Is(err, ErrClosed) {
		t.Errorf("Join after Close = %v, want %v", err, ErrClosed)
	}
	if _, _, err := n.Found(ctx, "#late2", nil); !errors.Is(err, ErrClosed) {
		t.Errorf("Found after Close = %v, want %v", err, ErrClosed)
	}
	if got := n.Channels(); len(got) != 0 {
		t.Errorf("closed node has %d channels", len(got))
	}
}

// TestPartTwiceKeepsTheRejoinedChannel checks that parting a channel
// object again after the node has rejoined by that name leaves the
// rejoined channel alone. Part forgot the channel by name, so the stale
// object's second Part unregistered the live one, which kept running
// with nothing able to reach it.
func TestPartTwiceKeepsTheRejoinedChannel(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	n := newTestNode(t, ctx, "self")
	old, err := n.Join(ctx, "#again", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := old.Part(ctx, ""); err != nil {
		t.Fatal(err)
	}
	live, err := n.Join(ctx, "#again", nil)
	if err != nil {
		t.Fatal(err)
	}
	_ = old.Part(ctx, "")
	if got, ok := n.Channel("#again"); !ok || got != live {
		t.Fatalf("Channel(#again) = %p, %v after a stale Part; want the rejoined %p", got, ok, live)
	}
}

// TestQuickRejoinIsHeard checks that a node is heard on a channel it
// left before its neighbor's answer to its join arrived. go-iroh gossip
// (v0.2.1) then owes that answer for good and answers none of the node's
// later joins, so the node, back on the channel, heard it and was never
// heard by it; see [Channel.overdue]. A subscription closed as soon as it
// is made is the way to lose the answer every time.
func TestQuickRejoinIsHeard(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	alice := newTestNode(t, ctx, "alice")
	carol := newTestNode(t, ctx, "carol")
	ac, err := alice.Join(ctx, "#quick", nil)
	if err != nil {
		t.Fatal(err)
	}
	boot := []netaddr.EndpointAddr{alice.Addr()}
	topic, err := carol.g.Subscribe(ctx, TopicID("#quick", nil), boot)
	if err != nil {
		t.Fatal(err)
	}
	_ = topic.Close()
	// The answer is sent once alice has carol for a neighbor, and is lost
	// if it arrives before carol is back.
	waitFor(t, ctx, func() bool { return slices.Contains(ac.Neighbors(), carol.ID()) }, "alice to take carol for a neighbor")
	time.Sleep(200 * time.Millisecond)
	if _, err := carol.Join(ctx, "#quick", boot); err != nil {
		t.Fatal(err)
	}
	wantRoster(t, ctx, ac, alice.ID(), carol.ID())
}

func TestOverdue(t *testing.T) {
	now := time.Now()
	id := func() key.EndpointID { return newKey(t).Public().EndpointID() }
	heard, quiet, fresh, gone := id(), id(), id(), id()
	c := &Channel{members: map[key.EndpointID]*member{
		heard: {seen: now},
		quiet: {seen: now.Add(-2 * presenceTimeout)},
	}}
	c.unheard = map[key.EndpointID]time.Time{
		heard: now.Add(-2 * presenceTimeout),
		quiet: now.Add(-presenceTimeout),
		gone:  now.Add(-2 * presenceTimeout),
	}
	got := c.overdue([]key.EndpointID{heard, quiet, fresh}, now)
	if len(got) != 1 || got[0] != quiet {
		t.Errorf("overdue = %v, want [%v]", got, quiet.Short())
	}
	want := map[key.EndpointID]time.Time{quiet: now, fresh: now}
	if !maps.Equal(c.unheard, want) {
		t.Errorf("unheard = %v, want %v", c.unheard, want)
	}
	// Just returned, quiet is not due again until a presenceTimeout on.
	if got := c.overdue([]key.EndpointID{quiet}, now.Add(presenceTimeout/2)); len(got) != 0 {
		t.Errorf("overdue again at once = %v, want none", got)
	}
	if got := c.overdue([]key.EndpointID{quiet}, now.Add(presenceTimeout)); len(got) != 1 {
		t.Errorf("overdue a presenceTimeout later = %v, want [%v]", got, quiet.Short())
	}
}
