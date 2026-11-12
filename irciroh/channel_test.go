package irciroh

import (
	"context"
	"testing"
	"time"

	"github.com/tmc/go-iroh/gossip"
	"github.com/tmc/go-iroh/key"
)

// TestChannelReportsUnverifiedEnvelope checks the first one is said at
// once: a node that cannot read its peers must not wait half a minute
// to say so the first time.
func TestChannelReportsUnverifiedEnvelope(t *testing.T) {
	c := &Channel{name: "#test", events: make(chan Event, 4)}

	c.handle(gossip.Event{Kind: gossip.Received, Content: []byte("not an envelope")})

	if got := c.Unverified(); got != 1 {
		t.Fatalf("Unverified() = %d, want 1", got)
	}
	ev := <-c.events
	if ev.Kind != Refused {
		t.Fatalf("event kind = %v, want %v", ev.Kind, Refused)
	}
	if !ev.From.ID.IsZero() {
		t.Fatalf("event attributed to %v, want no sender", ev.From.ID)
	}
	if ev.Text != "an envelope did not verify, from a neighbor" {
		t.Fatalf("event text = %q", ev.Text)
	}
}

// TestChannelDoesNotReportEveryUnverifiedEnvelope is the one that
// matters. The failure this counter exists for is a whole shore of the
// gossip mesh signing differently, so the envelopes that do not verify
// are not a trickle, they are everything that side says. Counting them
// all and saying so once is the difference between a diagnosis and a
// flood.
func TestChannelDoesNotReportEveryUnverifiedEnvelope(t *testing.T) {
	c := &Channel{name: "#test", events: make(chan Event, 64)}

	for range 20 {
		c.handle(gossip.Event{Kind: gossip.Received, Content: []byte("not an envelope")})
	}
	if got := c.Unverified(); got != 20 {
		t.Fatalf("Unverified() = %d, want 20", got)
	}
	if got := len(c.events); got != 1 {
		t.Fatalf("%d events for 20 drops, want 1", got)
	}

	// The next report carries what went unsaid in between, so a run
	// that is still going reads differently from one that stopped.
	<-c.events
	c.mu.Lock()
	c.unverifiedRun.reported = time.Now().Add(-2 * refusalReport)
	c.mu.Unlock()
	c.handle(gossip.Event{Kind: gossip.Received, Content: []byte("not an envelope")})
	ev := <-c.events
	if ev.Text != "20 envelopes did not verify in the last 30s, the nearest of them from a neighbor" {
		t.Fatalf("event text = %q, want the 19 unreported plus this one", ev.Text)
	}
}

// TestChannelSaysHowFarAnUnverifiedEnvelopeCame holds the distinction
// four sessions spent an afternoon patching this package to see. An
// envelope that does not verify names nobody, so the only thing left
// worth saying about it is how it arrived, and the answer decides
// where to look: gossip forwards a swarm-scoped message before this
// package sees it, so an unreadable envelope delivered at round zero
// was signed by a peer this node is meshed with, and one delivered
// further out was only passed on by whoever handed it over.
func TestChannelSaysHowFarAnUnverifiedEnvelopeCame(t *testing.T) {
	for _, tt := range []struct {
		round uint16
		want  string
	}{
		{0, "an envelope did not verify, from a neighbor"},
		{1, "an envelope did not verify, one forward away"},
		{2, "an envelope did not verify, 2 forwards away"},
	} {
		c := &Channel{name: "#test", events: make(chan Event, 4)}
		c.handle(gossip.Event{Kind: gossip.Received, Content: []byte("not an envelope"), Round: tt.round})
		if ev := <-c.events; ev.Text != tt.want {
			t.Errorf("round %d: event text = %q, want %q", tt.round, ev.Text, tt.want)
		}
	}
}

// TestChannelForgetsHowFarTheLastRunCame is the control on the one
// that matters. The nearest is a property of the run being reported,
// not of the channel, and a nearest that is never cleared latches:
// one envelope from a neighbor, and every report for the life of the
// channel says a neighbor signs differently, long after that neighbor
// has gone. That is worse than not saying it at all, because "look at
// your own mesh" is the reading an operator acts on.
func TestChannelForgetsHowFarTheLastRunCame(t *testing.T) {
	c := &Channel{name: "#test", events: make(chan Event, 8)}
	junk := []byte("not an envelope")

	// One run with a neighbor in it, reported and done with.
	c.handle(gossip.Event{Kind: gossip.Received, Content: junk, Round: 0})
	if ev := <-c.events; ev.Text != "an envelope did not verify, from a neighbor" {
		t.Fatalf("first report = %q", ev.Text)
	}

	// A second run with nothing adjacent in it. Crossing the reporting
	// interval is what makes it a second run rather than more of the
	// first; see TestChannelDoesNotReportEveryUnverifiedEnvelope.
	c.handle(gossip.Event{Kind: gossip.Received, Content: junk, Round: 3})
	c.mu.Lock()
	c.unverifiedRun.reported = time.Now().Add(-2 * refusalReport)
	c.mu.Unlock()
	c.handle(gossip.Event{Kind: gossip.Received, Content: junk, Round: 2})

	want := "2 envelopes did not verify in the last 30s, the nearest of them 2 forwards away"
	if ev := <-c.events; ev.Text != want {
		t.Fatalf("second report = %q, want %q", ev.Text, want)
	}
}

// TestSplitTextStopsAtTheNeighborCount holds the one distinction the
// sentence is for. What a reader does about several members going at
// once depends entirely on whether this node still has a mesh, and the
// text says which without saying what it means, because from here the
// two cases it leaves open are the same observation.
func TestSplitTextStopsAtTheNeighborCount(t *testing.T) {
	for _, tt := range []struct {
		gone, neighbors int
		want            string
	}{
		{2, 0, "2 members timed out together; this node has no neighbors"},
		{2, 1, "2 members timed out together; this node has 1 neighbor"},
		{5, 3, "5 members timed out together; this node has 3 neighbors"},
	} {
		if got := splitText(tt.gone, tt.neighbors); got != tt.want {
			t.Errorf("splitText(%d, %d) = %q, want %q", tt.gone, tt.neighbors, got, tt.want)
		}
	}
}

// joinAlone returns a public channel on a real node with nobody else in
// it, for a test that delivers envelopes to it by hand. It is not
// joined: nothing sweeps it for timeouts, so what a test finds in it is
// what the test delivered.
func joinAlone(t *testing.T, name string) *Channel {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	n := newTestNode(t, ctx, "self")
	c := &Channel{
		node:    n,
		name:    name,
		events:  make(chan Event, 16),
		members: make(map[key.EndpointID]*member),
		lastSeq: make(seqSet),
		spent:   make(budgets),
	}
	c.touch(n.ID(), "self", time.Now())
	return c
}

// deliver hands c one envelope signed by sk, as gossip would.
func deliver(t *testing.T, c *Channel, sk key.SecretKey, k kind, seq uint64, text string) {
	t.Helper()
	c.handle(gossip.Event{Kind: gossip.Received, Content: mustSign(t, sk, c.domain(), k, seq, text)})
}

// heard returns the texts of the Message events c has queued, and
// discards the rest.
func heard(c *Channel) []string {
	var out []string
	for {
		select {
		case ev := <-c.events:
			if ev.Kind == Message {
				out = append(out, ev.Text)
			}
		default:
			return out
		}
	}
}

func newKey(t *testing.T) key.SecretKey {
	t.Helper()
	sk, err := key.GenerateSecretKey()
	if err != nil {
		t.Fatal(err)
	}
	return sk
}

// TestChannelTakesReorderedEnvelopes holds the live path to the window:
// gossip may deliver a sender's envelopes out of order, and the earlier
// one is still a line that was said.
func TestChannelTakesReorderedEnvelopes(t *testing.T) {
	c := joinAlone(t, "#reorder")
	sk := newKey(t)
	deliver(t, c, sk, kindMessage, 7, "second")
	deliver(t, c, sk, kindMessage, 6, "first")
	deliver(t, c, sk, kindMessage, 6, "first")
	if got := heard(c); len(got) != 2 || got[0] != "second" || got[1] != "first" {
		t.Errorf("heard %q, want both lines once each", got)
	}
}

// TestChannelRefusesReplayAfterPart checks that a member's departure
// does not make its recent envelopes new again. Forgetting its window on
// part let anybody holding them put the member back in the roster and
// repeat what it said.
func TestChannelRefusesReplayAfterPart(t *testing.T) {
	c := joinAlone(t, "#replay")
	sk := newKey(t)
	line := mustSign(t, sk, c.domain(), kindMessage, 5, "once")
	c.handle(gossip.Event{Kind: gossip.Received, Content: line})
	deliver(t, c, sk, kindPart, 6, "")
	heard(c)

	c.handle(gossip.Event{Kind: gossip.Received, Content: line})
	if got := heard(c); len(got) != 0 {
		t.Errorf("a departed member's line played back as %q", got)
	}
	c.mu.Lock()
	_, back := c.members[sk.Public().EndpointID()]
	c.mu.Unlock()
	if back {
		t.Error("a replay put a departed member back in the roster")
	}
}

// TestSeqSetForgetsOnlyWhatTheClockRefuses holds seqIdle to its claim:
// a window is kept until everything it accepted is too old to accept
// anyway, so forgetting it lets nothing back in.
func TestSeqSetForgetsOnlyWhatTheClockRefuses(t *testing.T) {
	from := newKey(t).Public().EndpointID()
	now := time.Now()
	// The worst case is an envelope stamped as far ahead as accept
	// allows, since it stays young longest.
	e := envelope{Seq: 1, Time: now.Add(maxClockSkew).UnixMilli()}
	s := make(seqSet)
	if !s.accept(from, e, now) {
		t.Fatal("first delivery refused")
	}

	s.prune(now.Add(seqIdle - time.Second))
	if _, ok := s[from]; !ok {
		t.Fatalf("window forgotten before %v", seqIdle)
	}
	later := now.Add(seqIdle + time.Second)
	s.prune(later)
	if _, ok := s[from]; ok {
		t.Fatalf("window kept after %v", seqIdle)
	}
	if s.accept(from, e, later) {
		t.Error("a forgotten window let its envelope back in")
	}
}

// TestSealedTimeoutKeepsRank checks that on a sealed channel presence
// does not decide membership. A member that stops answering pings is
// still on the roster, so it keeps its rank and can still be granted
// one, until the founder removes it.
func TestSealedTimeoutKeepsRank(t *testing.T) {
	founder, op := testID(t), testID(t)
	c, now := sealedFixture(founder, op)
	c.members[op].rank = Operator
	c.members[op].seen = now.Add(-2 * presenceTimeout)

	gone, stale := c.timeouts(founder, now)
	if len(gone) != 0 {
		t.Errorf("a sealed timeout reported %d partings, want none", len(gone))
	}
	if len(stale) != 1 || stale[0] != op {
		t.Errorf("stale = %v, want the silent member for the founder to remove", stale)
	}
	if c.members[op] == nil {
		t.Fatal("a sealed timeout dropped a member still on the roster")
	}
	if got := c.rank(op); got != Operator {
		t.Errorf("rank after timeout = %v, want %v", got, Operator)
	}

	// A public channel has no roster but presence, so the same silence
	// is a departure there.
	p := &Channel{node: &Node{}, members: make(map[key.EndpointID]*member), lastSeq: make(seqSet), spent: make(budgets)}
	self, other := testID(t), testID(t)
	p.touch(self, "", now)
	p.touch(other, "", now.Add(-2*presenceTimeout))
	p.lastSeq[other] = &seqWindow{top: 1, seen: 1, last: now.Add(-2 * seqIdle)}
	gone, stale = p.timeouts(self, now)
	if len(gone) != 1 || gone[0].From.ID != other || len(stale) != 0 || p.members[other] != nil {
		t.Errorf("public timeout: gone %v, stale %v, still listed %v", gone, stale, p.members[other] != nil)
	}
	if len(p.lastSeq) != 0 {
		t.Error("the sweep kept a window idle for longer than seqIdle")
	}
}

// TestChannelDropsControlCharacters checks the receive path end to end:
// a correctly signed envelope whose text would split a line in whatever
// renders it is counted as unverified and never shown.
func TestChannelDropsControlCharacters(t *testing.T) {
	c := joinAlone(t, "#crlf")
	sk := newKey(t)
	c.handle(gossip.Event{Kind: gossip.Received, Content: forge(t, sk, c.domain(), kindMessage, 1, "mallory", "hi\r\nPRIVMSG #crlf :injected")})
	deliver(t, c, sk, kindMessage, 2, "clean")
	if got := heard(c); len(got) != 1 || got[0] != "clean" {
		t.Errorf("heard %q, want only the clean line", got)
	}
	if got := c.Unverified(); got != 1 {
		t.Errorf("Unverified() = %d, want 1", got)
	}
}

// TestChannelLateEnvelopeKeepsNewerNick checks that a line gossip
// delivers late does not rename its sender back to the nick it was sent
// under. Reordering is accepted within the replay window, so without
// this a rename was undone until the sender's next ping.
func TestChannelLateEnvelopeKeepsNewerNick(t *testing.T) {
	c := joinAlone(t, "#late")
	sk := newKey(t)
	id := sk.Public().EndpointID()
	nick := func() string {
		c.mu.Lock()
		defer c.mu.Unlock()
		return c.members[id].nick
	}
	renames := func() (n int) {
		for {
			select {
			case ev := <-c.events:
				if ev.Kind == NickChanged {
					n++
				}
			default:
				return n
			}
		}
	}
	send := func(k kind, seq uint64, nick, text string) {
		c.handle(gossip.Event{Kind: gossip.Received, Content: forge(t, sk, c.domain(), k, seq, nick, text)})
	}

	// Presence carries a nick as surely as speech does, and is what a
	// newcomer's budget allows the most of.
	send(kindJoin, 5, "bob", "")
	send(kindNick, 7, "robert", "robert")
	send(kindPing, 6, "bob", "")
	if got := nick(); got != "robert" {
		t.Errorf("after a late ping the nick is %q, want robert", got)
	}
	renames()

	send(kindPing, 10, "rob", "")
	send(kindNick, 9, "bobby", "bobby")
	if got := nick(); got != "rob" {
		t.Errorf("after a late rename the nick is %q, want rob", got)
	}
	if n := renames(); n != 0 {
		t.Errorf("a late rename reported %d nick changes, want none", n)
	}
}
