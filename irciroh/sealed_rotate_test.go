package irciroh

import (
	"context"
	"slices"
	"testing"
	"time"

	"github.com/tmc/go-iroh/postcard"
	"github.com/tmc/mls"
)

// TestNetworkSealedRotateThree checks that a rotation reaches every
// member, not only the founder and the member that proposed it. The
// founder's commit names the proposal by reference, so a member that
// had not kept the proposal could not apply the commit, and in a
// channel of three or more everyone else fell behind and rejoined on
// every rotation.
func TestNetworkSealedRotateThree(t *testing.T) {
	if testing.Short() {
		t.Skip("network test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	alice := newTestNode(t, ctx, "alice")
	bob := newTestNode(t, ctx, "bob")
	carol := newTestNode(t, ctx, "carol")
	room, ticket, err := alice.Found(ctx, "#vault", nil)
	if err != nil {
		t.Fatal(err)
	}
	bobRoom, err := bob.JoinTicket(ctx, ticket)
	if err != nil {
		t.Fatal(err)
	}
	carolRoom, err := carol.JoinTicket(ctx, ticket)
	if err != nil {
		t.Fatal(err)
	}
	rooms := []*Channel{room, bobRoom, carolRoom}
	for _, c := range rooms {
		wantRoster(t, ctx, c, alice.ID(), bob.ID(), carol.ID())
	}
	before := room.seal.epoch()
	waitFor(t, ctx, func() bool {
		return bobRoom.seal.epoch() == before && carolRoom.seal.epoch() == before
	}, "every member reaching alice's epoch")
	// heardSince reports whether every member has heard from every
	// other since a given time. A commit puts a member on the roster;
	// only a note from it shows that gossip reaches it, and a rotation
	// proposed before that is one a member can miss for want of a
	// neighbor.
	heardSince := func(since time.Time) bool {
		for _, c := range rooms {
			for _, m := range c.Members() {
				if m.Nick == "" || m.Seen.Before(since) {
					return false
				}
			}
		}
		return true
	}
	waitFor(t, ctx, func() bool { return heardSince(time.Time{}) }, "every member hearing every other")
	resynced := func(c *Channel) time.Time {
		c.seal.mu.Lock()
		defer c.seal.mu.Unlock()
		return c.seal.lastResync
	}
	bobResync, carolResync := resynced(bobRoom), resynced(carolRoom)

	if err := bobRoom.seal.rotate(ctx); err != nil {
		t.Fatal(err)
	}
	waitFor(t, ctx, func() bool {
		return room.seal.staged() > 0 && carolRoom.seal.staged() > 0
	}, "alice and carol staging bob's rotation")
	if err := room.seal.flush(ctx); err != nil {
		t.Fatal(err)
	}
	waitFor(t, ctx, func() bool {
		return bobRoom.seal.epoch() > before && carolRoom.seal.epoch() > before
	}, "bob and carol applying the rotation")

	// Traffic in the new epoch is what would tell a member that missed
	// the commit that it is behind, so wait for several presence
	// intervals of it to have been heard, however long that takes.
	after := time.Now().Add(5 * presenceInterval)
	waitFor(t, ctx, func() bool { return heardSince(after) }, "every member hearing every other in the new epoch")
	for _, c := range rooms {
		if got := c.seal.epoch(); got != before+1 {
			t.Errorf("%s is at epoch %d, want %d", c.node.Nick(), got, before+1)
		}
	}
	if !resynced(bobRoom).Equal(bobResync) || !resynced(carolRoom).Equal(carolResync) {
		t.Error("a member rejoined after the rotation")
	}

	if err := carolRoom.Say(ctx, "still here"); err != nil {
		t.Fatal(err)
	}
	ev := await(t, ctx, events(t, bobRoom), ofKind(Message), "bob reading carol after the rotation")
	if ev.Text != "still here" {
		t.Fatalf("bob got %q", ev.Text)
	}
}

// sealedPair returns a founder's channel and a member's, both settled in
// the same epoch.
func sealedPair(t *testing.T, ctx context.Context) (founder, member *Channel) {
	t.Helper()
	alice := newTestNode(t, ctx, "alice")
	bob := newTestNode(t, ctx, "bob")
	room, ticket, err := alice.Found(ctx, "#vault", nil)
	if err != nil {
		t.Fatal(err)
	}
	bobRoom, err := bob.JoinTicket(ctx, ticket)
	if err != nil {
		t.Fatal(err)
	}
	wantRoster(t, ctx, room, alice.ID(), bob.ID())
	waitFor(t, ctx, func() bool { return bobRoom.seal.epoch() == room.seal.epoch() }, "bob reaching alice's epoch")
	return room, bobRoom
}

// sealIn seals a note from g's own leaf, without touching any channel.
func sealIn(t *testing.T, g *mls.Group, seq uint64, text string) []byte {
	t.Helper()
	plain, err := postcard.Marshal(note{Version: noteVersion, Kind: uint8(kindMessage), Seq: seq, Time: time.Now().UnixMilli(), Nick: "alice", Text: text})
	if err != nil {
		t.Fatal(err)
	}
	msg, err := g.Protect(nil, plain)
	if err != nil {
		t.Fatal(err)
	}
	b, err := mls.Marshal(msg)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// said returns the texts of the Message events in out.
func said(out []Event) []string {
	var s []string
	for _, ev := range out {
		if ev.Kind == Message {
			s = append(s, ev.Text)
		}
	}
	return s
}

// TestSealedNextEpochHeld checks that a message which overtakes the
// commit starting its epoch is held and delivered once the commit
// lands, rather than making the member rejoin. A member rejoins only
// when it is two epochs behind, or still one behind after aheadGrace.
func TestSealedNextEpochHeld(t *testing.T) {
	if testing.Short() {
		t.Skip("network test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	room, bobRoom := sealedPair(t, ctx)

	// Alice commits without gossiping, so the order bob sees is the one
	// written here.
	room.seal.mu.Lock()
	next, commit, _, err := room.seal.group.Commit(nil)
	room.seal.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	commitBytes, err := mls.Marshal(commit)
	if err != nil {
		t.Fatal(err)
	}
	later, _, _, err := next.Commit(nil)
	if err != nil {
		t.Fatal(err)
	}
	early := sealIn(t, next, 1<<40, "early")

	if out, behind := bobRoom.seal.receive(early); len(out) != 0 || behind {
		t.Fatalf("a message from the next epoch gave %v, behind %v; want it held", out, behind)
	}
	// Two epochs ahead is a commit missed, not one overtaken.
	if _, behind := bobRoom.seal.receive(sealIn(t, later, 1<<40+1, "later")); !behind {
		t.Fatal("a message two epochs ahead did not report the member behind")
	}
	out, behind := bobRoom.seal.receive(commitBytes)
	if behind {
		t.Fatal("the commit reported the member behind")
	}
	if got := said(out); len(got) != 1 || got[0] != "early" {
		t.Fatalf("applying the commit delivered %q, want the held message", got)
	}
	room.seal.mu.Lock()
	room.seal.group = next
	room.seal.mu.Unlock()

	// Still one behind after the grace period is a commit missed.
	bobRoom.seal.mu.Lock()
	stale, _, _, err := bobRoom.seal.group.Commit(nil)
	bobRoom.seal.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	if _, behind := bobRoom.seal.receive(sealIn(t, stale, 1<<40+2, "one")); behind {
		t.Fatal("the first message from the next epoch reported the member behind")
	}
	bobRoom.seal.mu.Lock()
	bobRoom.seal.aheadSince = time.Now().Add(-aheadGrace())
	bobRoom.seal.mu.Unlock()
	if _, behind := bobRoom.seal.receive(sealIn(t, stale, 1<<40+3, "two")); !behind {
		t.Fatal("a member still behind after the grace period was not reported behind")
	}
}

// TestSealedHeldCommitLast checks that a held commit is applied after the
// messages held with it. It ends the epoch they were sent in, so applied
// first it would leave them behind; the commit is told apart before it
// is opened by the content type in its header.
func TestSealedHeldCommitLast(t *testing.T) {
	if testing.Short() {
		t.Skip("network test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	room, bobRoom := sealedPair(t, ctx)

	room.seal.mu.Lock()
	next, first, _, err := room.seal.group.Commit(nil)
	room.seal.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	last, second, _, err := next.Commit(nil)
	if err != nil {
		t.Fatal(err)
	}
	firstBytes, err := mls.Marshal(first)
	if err != nil {
		t.Fatal(err)
	}
	secondBytes, err := mls.Marshal(second)
	if err != nil {
		t.Fatal(err)
	}

	// Both arrive ahead of the commit that starts their epoch, the
	// second commit first.
	for _, b := range [][]byte{secondBytes, sealIn(t, next, 1<<40, "early")} {
		if out, behind := bobRoom.seal.receive(b); len(out) != 0 || behind {
			t.Fatalf("a message from the next epoch gave %v, behind %v; want it held", out, behind)
		}
	}
	out, behind := bobRoom.seal.receive(firstBytes)
	if behind {
		t.Fatal("the commit reported the member behind")
	}
	if got := said(out); len(got) != 1 || got[0] != "early" {
		t.Fatalf("applying the commit delivered %q, want the held message", got)
	}
	if got, want := bobRoom.seal.epoch(), last.Epoch(); got != want {
		t.Fatalf("bob is in epoch %d, want %d: the held commit was not applied", got, want)
	}
}

// TestSealedReorderedNotes checks that two notes from one sender are
// both delivered when the later one arrives first. mls keeps the keys
// of the generations a receiver skips, so the earlier note can still
// be opened.
func TestSealedReorderedNotes(t *testing.T) {
	if testing.Short() {
		t.Skip("network test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	room, bobRoom := sealedPair(t, ctx)

	first, err := bobRoom.seal.seal(kindMessage, "first", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	second, err := bobRoom.seal.seal(kindMessage, "second", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if out, _ := room.seal.receive(second); len(said(out)) != 1 {
		t.Fatalf("the second note gave %v", out)
	}
	if got := said(func() []Event { out, _ := room.seal.receive(first); return out }()); len(got) != 1 || got[0] != "first" {
		t.Fatalf("the first note, arriving second, gave %q", got)
	}
}

// TestSealedFutureClock checks that a note stamped far ahead cannot
// freeze a topic: it counts as said on arrival, so a later statement
// still supersedes it.
func TestSealedFutureClock(t *testing.T) {
	if testing.Short() {
		t.Skip("network test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	room, bobRoom := sealedPair(t, ctx)

	ahead, err := bobRoom.seal.seal(kindTopic, "frozen", time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	out, _ := room.seal.receive(ahead)
	i := slices.IndexFunc(out, ofKind(TopicChanged))
	if i < 0 {
		t.Fatalf("the topic stamped ahead gave %v", out)
	}
	if out[i].Time.After(time.Now()) {
		t.Fatalf("the topic stamped ahead kept its time %v", out[i].Time)
	}
	next, err := bobRoom.seal.seal(kindTopic, "thawed", time.Now().Add(maxClockSkew/2))
	if err != nil {
		t.Fatal(err)
	}
	room.seal.receive(next)
	if topic, _, _, _ := room.Topic(); topic != "thawed" {
		t.Fatalf("topic is %q, want the later statement", topic)
	}
}

// TestSealedFlushEmpty checks that the founder does not spend an epoch
// on a commit that would carry nothing, whatever it believes is staged.
func TestSealedFlushEmpty(t *testing.T) {
	if testing.Short() {
		t.Skip("network test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	room, _ := sealedPair(t, ctx)

	before := room.seal.epoch()
	room.seal.mu.Lock()
	room.seal.pending = map[mls.LeafIndex]bool{99: true}
	room.seal.mu.Unlock()
	if err := room.seal.flush(ctx); err != nil {
		t.Fatal(err)
	}
	if got := room.seal.epoch(); got != before {
		t.Fatalf("an empty flush moved the epoch from %d to %d", before, got)
	}
}

// TestNetworkSealedRotateTwice checks a member that proposes a second
// rotation before the founder has committed the first, as happens when
// a founder's flush misses a rotation interval. The founder holds both
// updates for one leaf; its commit can carry only one, and the member
// must apply it whichever it is, without rejoining.
func TestNetworkSealedRotateTwice(t *testing.T) {
	if testing.Short() {
		t.Skip("network test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	room, bobRoom := sealedPair(t, ctx)
	before := room.seal.epoch()
	key0 := leafEncryptionKey(t, bobRoom.seal)
	bobRoom.seal.mu.Lock()
	sig0 := string(bobRoom.seal.group.Tree.Leaf(bobRoom.seal.group.Index).SignatureKey)
	resync := bobRoom.seal.lastResync
	bobRoom.seal.mu.Unlock()

	// The proposals are handed to the founder directly rather than
	// gossiped, so that both are known to be staged before it commits.
	var proposals [][]byte
	for range 2 {
		b, err := bobRoom.seal.proposeRotation()
		if err != nil {
			t.Fatal(err)
		}
		proposals = append(proposals, b)
	}
	room.seal.mu.Lock()
	for _, b := range proposals {
		room.seal.open(b, time.Now())
	}
	room.seal.mu.Unlock()
	if got := room.seal.staged(); got != 1 {
		t.Fatalf("founder has %d leaves staged, want 1", got)
	}

	if err := room.seal.flush(ctx); err != nil {
		t.Fatal(err)
	}
	waitFor(t, ctx, func() bool { return bobRoom.seal.epoch() > before }, "bob applying the rotation")
	if got := bobRoom.seal.epoch(); got != before+1 {
		t.Fatalf("bob is at epoch %d, want %d", got, before+1)
	}
	if leafEncryptionKey(t, bobRoom.seal) == key0 {
		t.Fatal("bob's leaf encryption key did not change")
	}
	bobRoom.seal.mu.Lock()
	rejoined := !bobRoom.seal.lastResync.Equal(resync)
	bobRoom.seal.mu.Unlock()
	if rejoined {
		t.Fatal("bob rejoined instead of applying the commit")
	}
	bobRoom.seal.mu.Lock()
	sig1 := string(bobRoom.seal.group.Tree.Leaf(bobRoom.seal.group.Index).SignatureKey)
	bobRoom.seal.mu.Unlock()
	if sig1 == sig0 {
		t.Fatal("bob's leaf signature key did not change")
	}

	// Sending proves that the accepted successor activated the new private
	// signing key, not just the public key in the tree.
	if err := bobRoom.Say(ctx, "new signer"); err != nil {
		t.Fatal(err)
	}
	ev := await(t, ctx, events(t, room), ofKind(Message), "founder reading bob's new signer")
	if ev.Text != "new signer" {
		t.Fatalf("founder got %q", ev.Text)
	}
	// A later rotation must sign its new leaf with fresh keys rather than
	// reuse the client's original signing key.
	b, err := bobRoom.seal.proposeRotation()
	if err != nil {
		t.Fatal(err)
	}
	room.seal.receive(b)
	if err := room.seal.flush(ctx); err != nil {
		t.Fatal(err)
	}
	waitFor(t, ctx, func() bool { return bobRoom.seal.epoch() == before+2 }, "bob applying another rotation")
	if err := room.Say(ctx, "rotated twice"); err != nil {
		t.Fatal(err)
	}
	ev = await(t, ctx, events(t, bobRoom), ofKind(Message), "bob reading after the rotation")
	if ev.Text != "rotated twice" {
		t.Fatalf("bob got %q", ev.Text)
	}
}
