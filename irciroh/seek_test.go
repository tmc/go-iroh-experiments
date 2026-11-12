package irciroh

import (
	"context"
	"errors"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/tmc/go-iroh/key"
	"github.com/tmc/go-iroh/netaddr"
)

// TestSeekKeepsLookingAfterLosingItsLastNeighbor holds the difference
// between finding a way in and keeping one. seek used to return the
// moment the channel had a neighbour, on the reasoning that from then
// on the swarm was the way in. The swarm is the way in only while this
// node is in it: gossip drops a neighbour when its peer goes away, so
// the node whose last neighbour restarts is back where it began, with
// nothing left running to look for another. That is not a rare case,
// it is what happens to everyone still up when a node they were paired
// with is restarted, and a fleet can sit in pieces indefinitely
// without a single error anywhere.
func TestSeekKeepsLookingAfterLosingItsLastNeighbor(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	alice := newTestNode(t, ctx, "alice")
	bob := newTestNode(t, ctx, "bob")

	ach, err := alice.JoinTicket(ctx, Ticket{Channel: "#seek"})
	if err != nil {
		t.Fatal(err)
	}
	bch, err := bob.JoinTicket(ctx, Ticket{Channel: "#seek", Peers: []netaddr.EndpointAddr{alice.Addr()}})
	if err != nil {
		t.Fatal(err)
	}
	waitNeighbors(t, bch, 1)

	// seek is started by the join only when the node has a rendezvous
	// to look in, so run it here directly: what is under test is when
	// it gives up, not what it finds.
	done := make(chan struct{})
	go func() {
		defer close(done)
		bch.seek()
	}()

	// With a neighbour, seek has nothing to do and must not exit.
	select {
	case <-done:
		t.Fatal("seek returned while the channel had a neighbour")
	case <-time.After(seekWatchInterval / 2):
	}

	// Alice goes away, which is a restart from bob's side.
	if err := ach.Part(ctx, ""); err != nil {
		t.Fatal(err)
	}
	waitNeighbors(t, bch, 0)

	// The regression: seek used to be gone by now, so nothing would
	// ever look for a way back in. It must still be running.
	select {
	case <-done:
		t.Fatal("seek returned after the last neighbour went away: a lost mesh is never repaired")
	case <-time.After(2 * time.Second):
	}

	// And it must still stop when the channel does, or every channel
	// ever joined leaks a goroutine for the life of the process.
	if err := bch.Part(ctx, ""); err != nil {
		t.Fatal(err)
	}
	select {
	case <-done:
	case <-time.After(30 * time.Second):
		t.Fatal("seek outlived the channel")
	}
}

// waitNeighbors waits for c to have exactly n neighbours.
func waitNeighbors(t *testing.T, c *Channel, n int) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for len(c.topic.Neighbors()) != n {
		if time.Now().After(deadline) {
			t.Fatalf("neighbours = %d, want %d", len(c.topic.Neighbors()), n)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// TestReachSurvivesARecordThatNamesNobody holds the contract seek
// depends on to keep running. reach reports whether the channel is
// still open, not whether it found anyone: a rendezvous record that
// names nobody, names this node, or cannot be resolved at all is the
// ordinary case for the first member of a channel, and treating it as
// a reason to stop is how a node stops looking for the rest of the
// room. Only the channel closing ends the search.
func TestReachSurvivesARecordThatNamesNobody(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	n := newTestNode(t, ctx, "alice")
	c, err := n.JoinTicket(ctx, Ticket{Channel: "#reach-nobody-9fc2"})
	if err != nil {
		t.Fatal(err)
	}
	// A channel nobody has ever announced: the lookup finds no record.
	n.rv = &rendezvous{}
	if !c.reach() {
		t.Fatal("reach reported the channel closed because the record named nobody")
	}
}

// TestReachCrossesTwoPockets holds what the periodic lookup is for.
// Two groups of the same channel that never meshed are each healthy
// from inside: neighbors, a roster, nothing to trigger on. Only a
// lookup made while holding a neighbor can join them, which is the one
// call a seek that stops at the first neighbor cannot make.
//
// The rendezvous is answered here rather than resolved, because the
// record is written to a public name service and a test cannot say who
// holds it. What is under test is what a node does with the answer.
func TestReachCrossesTwoPockets(t *testing.T) {
	if testing.Short() {
		t.Skip("network test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	alice := newTestNode(t, ctx, "alice")
	bob, carol := newTestNode(t, ctx, "bob"), newTestNode(t, ctx, "carol")

	// One pocket of one, and one pocket of two. Nobody has a way to
	// reach the other: no ticket names across, and no rendezvous.
	ach, err := alice.JoinTicket(ctx, Ticket{Channel: "#pockets"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := carol.JoinTicket(ctx, Ticket{Channel: "#pockets"}); err != nil {
		t.Fatal(err)
	}
	bch, err := bob.JoinTicket(ctx, Ticket{Channel: "#pockets", Peers: []netaddr.EndpointAddr{carol.Addr()}})
	if err != nil {
		t.Fatal(err)
	}
	waitNeighbors(t, bch, 1)
	if slices.Contains(bch.Neighbors(), alice.ID()) {
		t.Skip("bob meshed with alice without looking; the split this measures did not hold")
	}
	if n := len(ach.topic.Neighbors()); n != 0 {
		t.Fatalf("alice has %d neighbours in a channel nobody was told about", n)
	}

	// Bob asks where the channel is, holding a neighbor already, and
	// is told about the other pocket. This is the answer the record
	// gives whenever somebody other than bob's own pocket wrote it
	// last, which over a membership taking turns is often enough.
	bob.find = func(context.Context, string, []byte) (netaddr.EndpointAddr, error) {
		return alice.Addr(), nil
	}
	if !bch.reach() {
		t.Fatal("reach reported the channel closed")
	}

	deadline := time.Now().Add(30 * time.Second)
	for !slices.Contains(bch.Neighbors(), alice.ID()) {
		if time.Now().After(deadline) {
			t.Fatalf("bob's neighbours are %v; the lookup did not cross the pockets", bch.Neighbors())
		}
		time.Sleep(50 * time.Millisecond)
	}
	if n := len(ach.topic.Neighbors()); n == 0 {
		t.Error("alice is still alone: the join went one way")
	}
}

// TestANodeWithNoRendezvousDoesNotLookAnythingUp holds that seek's
// lookup is off unless [WithRendezvous] asked for it. The lookup went
// to a public name service through a method that ignores its receiver,
// so a nil rendezvous resolved rather than doing nothing, and every
// channel on every node queried the service on the seek cadence
// whether or not the node had opted in to being on it.
func TestANodeWithNoRendezvousDoesNotLookAnythingUp(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	n := newTestNode(t, ctx, "alice")
	if n.find != nil {
		t.Fatal("a node made without WithRendezvous will look channels up")
	}
	c, err := n.JoinTicket(ctx, Ticket{Channel: "#quiet"})
	if err != nil {
		t.Fatal(err)
	}
	if !c.reach() {
		t.Fatal("reach reported the channel closed")
	}
}

// TestSeekMergesTwoPocketsOnItsOwn is the one that fails against a
// seek that stops at the first neighbor. Nothing here calls reach:
// bob is left running the loop with a neighbor in hand and a record
// naming the other pocket, and the question is whether the loop ever
// asks. A seek that treats a neighbor as done never does, and bob
// stays where he is.
func TestSeekMergesTwoPocketsOnItsOwn(t *testing.T) {
	if testing.Short() {
		t.Skip("network test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	alice := newTestNode(t, ctx, "alice")
	bob, carol := newTestNode(t, ctx, "bob"), newTestNode(t, ctx, "carol")

	ach, err := alice.JoinTicket(ctx, Ticket{Channel: "#merge"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := carol.JoinTicket(ctx, Ticket{Channel: "#merge"}); err != nil {
		t.Fatal(err)
	}
	// Bob can look the channel up but does not announce: seek is
	// gated on being able to ask, which is what this sets, and the
	// answer is given here rather than resolved from a public record.
	// His cadences are set before he joins, so the loop reads what
	// nothing else writes.
	bob.watch, bob.merge = 100*time.Millisecond, 250*time.Millisecond
	bob.find = func(context.Context, string, []byte) (netaddr.EndpointAddr, error) {
		return alice.Addr(), nil
	}
	bch, err := bob.JoinTicket(ctx, Ticket{Channel: "#merge", Peers: []netaddr.EndpointAddr{carol.Addr()}})
	if err != nil {
		t.Fatal(err)
	}
	waitNeighbors(t, bch, 1)
	if slices.Contains(bch.Neighbors(), alice.ID()) {
		t.Skip("bob meshed with alice without looking; the split this measures did not hold")
	}

	deadline := time.Now().Add(30 * time.Second)
	for !slices.Contains(bch.Neighbors(), alice.ID()) {
		if time.Now().After(deadline) {
			t.Fatalf("bob held %v for the whole run and never looked for anybody else", bch.Neighbors())
		}
		time.Sleep(50 * time.Millisecond)
	}
	if n := len(ach.topic.Neighbors()); n == 0 {
		t.Error("alice is still alone")
	}
}

// TestReachedDoesNotCountThisNode holds the two properties seek now
// rests on. A node is always in its own roster, so a roster that is not
// empty is not a way in - counting it would make a node alone in a
// channel believe it had arrived and stop looking, which is the bug
// seek exists to avoid. And a peer enters the roster only once
// something it sent has been verified, which is what makes the roster
// say more than the neighbour set does.
func TestReachedDoesNotCountThisNode(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	alice := newTestNode(t, ctx, "alice")
	bob := newTestNode(t, ctx, "bob")

	ach, err := alice.JoinTicket(ctx, Ticket{Channel: "#reached"})
	if err != nil {
		t.Fatal(err)
	}
	if got := len(ach.Members()); got != 1 {
		t.Fatalf("alice alone has %d members, want herself", got)
	}
	if ach.reached() {
		t.Fatal("alice counts herself as a way into the channel")
	}

	bch, err := bob.JoinTicket(ctx, Ticket{Channel: "#reached", Peers: []netaddr.EndpointAddr{alice.Addr()}})
	if err != nil {
		t.Fatal(err)
	}
	waitReached(t, ach)
	waitReached(t, bch)
}

// waitReached waits for a channel to hold a member other than its own
// node. Attaching is not enough: the peer has to have said something
// that verified, so this is slower than waiting for a neighbour and is
// the point of the difference.
func waitReached(t *testing.T, c *Channel) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for !c.reached() {
		if time.Now().After(deadline) {
			t.Fatalf("channel never reached anybody; members = %d, neighbours = %d",
				len(c.Members()), len(c.topic.Neighbors()))
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// TestReachedIgnoresTheSealedGroupRoster holds the difference between
// having been admitted and being here. On a sealed channel
// [Channel.Members] answers from the MLS group, which is who the
// founder let in and stays true after they have all gone: a founder
// that invited somebody and then lost every neighbour has a group of
// two and has reached nobody. seek would read that as a way in and stop
// looking, which is the case it exists for.
func TestReachedIgnoresTheSealedGroupRoster(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	alice := newTestNode(t, ctx, "alice")
	bob := newTestNode(t, ctx, "bob")

	room, ticket, err := alice.Found(ctx, "#vault", nil)
	if err != nil {
		t.Fatal(err)
	}
	ticket.Peers = []netaddr.EndpointAddr{alice.Addr()}
	if _, err := bob.JoinTicket(ctx, ticket); err != nil {
		t.Fatal(err)
	}
	waitReached(t, room)

	// Bob is in the group and has stopped being heard from. Nothing
	// about the group says so, which is the point.
	room.mu.Lock()
	for id, m := range room.members {
		if id != alice.ID() {
			m.seen = time.Now().Add(-2 * presenceTimeout)
		}
	}
	room.mu.Unlock()

	if n := len(room.Members()); n < 2 {
		t.Fatalf("sealed roster = %d, want the group to still hold bob", n)
	}
	if room.reached() {
		t.Error("a founder alone with a stale group counts it as a way in")
	}
}

// TestSeekDoesNotLookOnAFixedCadence holds the repair for the phase
// lock measured on 2026-09-19. Every member of a channel republishes
// the rendezvous record on its own fixed timer, and a record that
// holds one member at a time turns that into a rotation whose period
// is the timer; a node whose own lookup period is an integer multiple
// of it draws the same member forever. The published default for that
// timer and seekMergeInterval were both five minutes, and one field
// node made fourteen consecutive lookups over sixty-five minutes that
// all returned the same peer.
//
// The lock is invisible from inside - the answer verifies and names a
// live member - so what is under test is the only observable it has:
// that the gaps between lookups are not all the same. A constant
// cadence quantised by the watch tick would put every gap in one or
// two buckets.
//
// The member is written in rather than met, because what decides which
// branch of the loop runs is the roster and nothing here needs it to
// have come from the wire.
func TestSeekDoesNotLookOnAFixedCadence(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	n := newTestNode(t, ctx, "alice")

	var mu sync.Mutex
	var at []time.Time
	n.watch, n.merge = 10*time.Millisecond, 100*time.Millisecond
	n.find = func(context.Context, string, []byte) (netaddr.EndpointAddr, error) {
		mu.Lock()
		at = append(at, time.Now())
		mu.Unlock()
		return netaddr.EndpointAddr{}, errors.New("no record")
	}
	c, err := n.JoinTicket(ctx, Ticket{Channel: "#cadence-4b71"})
	if err != nil {
		t.Fatal(err)
	}

	// A peer in the roster, kept fresh, so seek stays in the branch
	// that looks slowly rather than the one that backs off.
	peer := key.NewSecretKey([32]byte{1}).Public().EndpointID()
	done := make(chan struct{})
	defer close(done)
	go func() {
		for {
			c.mu.Lock()
			c.members[peer] = &member{nick: "bob", seen: time.Now()}
			c.mu.Unlock()
			select {
			case <-done:
				return
			case <-time.After(5 * time.Millisecond):
			}
		}
	}()

	deadline := time.Now().Add(30 * time.Second)
	for {
		mu.Lock()
		got := len(at)
		mu.Unlock()
		if got >= 9 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("seek looked %d times in 30s; it should look about every %v", got, n.merge)
		}
		time.Sleep(20 * time.Millisecond)
	}

	mu.Lock()
	times := append([]time.Time(nil), at...)
	mu.Unlock()
	buckets := make(map[time.Duration]bool)
	for i := 1; i < len(times); i++ {
		buckets[times[i].Sub(times[i-1]).Round(10*time.Millisecond)] = true
	}
	if len(buckets) < 4 {
		t.Errorf("seek looked on %d distinct gaps across %d lookups; it is on a fixed cadence",
			len(buckets), len(times))
	}
}

// TestSpreadStaysWithinHalfAndAHalf holds the two properties seek
// rests on: a wait is scattered, and it is still recognisably the wait
// that was asked for.
func TestSpreadStaysWithinHalfAndAHalf(t *testing.T) {
	const d = time.Second
	seen := make(map[time.Duration]bool)
	for range 200 {
		got := spread(d)
		if got < d/2 || got >= d+d/2 {
			t.Fatalf("spread(%v) = %v, want within [%v, %v)", d, got, d/2, d+d/2)
		}
		seen[got] = true
	}
	if len(seen) < 100 {
		t.Errorf("200 draws of spread(%v) took %d distinct values", d, len(seen))
	}
	if got := spread(0); got != 0 {
		t.Errorf("spread(0) = %v, want 0", got)
	}
}
