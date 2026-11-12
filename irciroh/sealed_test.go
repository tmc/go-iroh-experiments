package irciroh

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/tmc/go-iroh/key"
	"github.com/tmc/go-iroh/postcard"
)

// TestNetworkSealed runs a sealed channel over three real loopback
// endpoints: the founder creates it, two members join on the ticket, and
// the three exchange messages that nobody outside the group could read.
// Membership is the group's roster rather than whoever is listening, and
// a removal makes what follows unreadable to the member removed.
func TestNetworkSealed(t *testing.T) {
	if testing.Short() {
		t.Skip("network test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	alice := newTestNode(t, ctx, "alice")
	bob := newTestNode(t, ctx, "bob")

	room, ticket, err := alice.Found(ctx, "#vault", nil)
	if err != nil {
		t.Fatal(err)
	}
	if !ticket.Sealed() || ticket.Founder != alice.ID() {
		t.Fatalf("ticket %+v does not name alice as founder", ticket)
	}
	// The ticket survives its string form, which is how it is handed
	// over in practice.
	got, err := ParseTicket(ticket.String())
	if err != nil {
		t.Fatal(err)
	}
	if got.Founder != alice.ID() || string(got.Secret) != string(ticket.Secret) {
		t.Fatalf("ticket did not round-trip: %+v", got)
	}

	aliceEvents := events(t, room)
	bobRoom, err := bob.JoinTicket(ctx, got)
	if err != nil {
		t.Fatal(err)
	}
	bobEvents := events(t, bobRoom)

	// Alice learns bob is in from the commit she made for him.
	await(t, ctx, aliceEvents, func(ev Event) bool {
		return ev.Kind == Joined && ev.From.ID == bob.ID()
	}, "alice seeing bob join")

	// Both rosters are the group's, not the topic's.
	wantRoster(t, ctx, room, alice.ID(), bob.ID())
	wantRoster(t, ctx, bobRoom, alice.ID(), bob.ID())

	// A message crosses the seal.
	if err := room.Say(ctx, "the eagle has landed"); err != nil {
		t.Fatal(err)
	}
	ev := await(t, ctx, bobEvents, ofKind(Message), "bob receiving alice's message")
	if ev.Text != "the eagle has landed" || ev.From.ID != alice.ID() {
		t.Fatalf("bob got %q from %v", ev.Text, ev.From.ID.Short())
	}
	// And bob is named by his leaf's binding, not by the transport.
	if err := bobRoom.Say(ctx, "copy that"); err != nil {
		t.Fatal(err)
	}
	ev = await(t, ctx, aliceEvents, ofKind(Message), "alice receiving bob's message")
	if ev.Text != "copy that" || ev.From.ID != bob.ID() {
		t.Fatalf("alice got %q from %v", ev.Text, ev.From.ID.Short())
	}

	// Carol has the ticket, so she gets in; the founder committed her
	// addition, so both existing members see it.
	carol := newTestNode(t, ctx, "carol")
	carolRoom, err := carol.JoinTicket(ctx, got)
	if err != nil {
		t.Fatal(err)
	}
	await(t, ctx, bobEvents, func(ev Event) bool {
		return ev.Kind == Joined && ev.From.ID == carol.ID()
	}, "bob seeing carol join")
	wantRoster(t, ctx, carolRoom, alice.ID(), bob.ID(), carol.ID())

	// Bob leaves. Only the founder can commit the removal, so bob's
	// part is a request and the roster changes when it lands.
	if err := bobRoom.Part(ctx, ""); err != nil {
		t.Fatal(err)
	}
	await(t, ctx, aliceEvents, func(ev Event) bool {
		return ev.Kind == Parted && ev.From.ID == bob.ID()
	}, "alice seeing bob leave")
	wantRoster(t, ctx, room, alice.ID(), carol.ID())
	wantRoster(t, ctx, carolRoom, alice.ID(), carol.ID())

	// What is said now is in an epoch bob has no key for. He is still
	// subscribed to the gossip topic and still receives the bytes.
	if err := room.Say(ctx, "change the locks"); err != nil {
		t.Fatal(err)
	}
	ev = await(t, ctx, events(t, carolRoom), ofKind(Message), "carol receiving the last message")
	if ev.Text != "change the locks" {
		t.Fatalf("carol got %q", ev.Text)
	}
}

// TestNetworkSealedUninvited checks that the secret is load-bearing and
// that the founder's policy is consulted on top of it.
func TestNetworkSealedUninvited(t *testing.T) {
	if testing.Short() {
		t.Skip("network test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	alice := newTestNode(t, ctx, "alice")
	bob := newTestNode(t, ctx, "bob")
	carol := newTestNode(t, ctx, "carol")

	// Alice admits bob and nobody else, whatever they present.
	_, ticket, err := alice.Found(ctx, "#vault", func(id key.EndpointID) bool {
		return id == bob.ID()
	})
	if err != nil {
		t.Fatal(err)
	}

	// The right ticket, the wrong endpoint.
	if _, err := carol.JoinTicket(ctx, ticket); !errors.Is(err, ErrNotInvited) {
		t.Fatalf("carol joined with the ticket: %v", err)
	}
	// The right endpoint, the wrong secret. The topic derives from the
	// secret, so a guessed secret does not name this channel at all:
	// bob reaches an empty topic and waits there, and the refusal he
	// gets is his own deadline rather than an answer from anyone. That
	// silence is the price of keeping the roster off the wire, so the
	// join needs a deadline of its own.
	wrong := ticket
	wrong.Secret = slices.Clone(ticket.Secret)
	wrong.Secret[0] ^= 1
	short, cancelShort := context.WithTimeout(ctx, 5*time.Second)
	_, err = bob.JoinTicket(short, wrong)
	cancelShort()
	if err == nil {
		t.Fatal("bob joined with a corrupted secret")
	}
	// The right ticket and the right endpoint.
	if _, err := bob.JoinTicket(ctx, ticket); err != nil {
		t.Fatal(err)
	}
}

// TestNetworkSealedFounderRefusesSelf checks that a founder cannot
// rejoin its own channel through the invite path, which would commit it
// in beside itself.
func TestNetworkSealedFounderRefusesSelf(t *testing.T) {
	if testing.Short() {
		t.Skip("network test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	alice := newTestNode(t, ctx, "alice")
	_, ticket, err := alice.Found(ctx, "#vault", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := alice.JoinTicket(ctx, ticket); err == nil {
		t.Fatal("the founder joined its own channel")
	}
}

// wantRoster waits until the channel's roster is exactly want.
func wantRoster(t *testing.T, ctx context.Context, c *Channel, want ...key.EndpointID) {
	t.Helper()
	slices.SortFunc(want, func(a, b key.EndpointID) int { return a.Compare(b) })
	for {
		got := make([]key.EndpointID, 0, len(want))
		for _, m := range c.Members() {
			got = append(got, m.ID)
		}
		slices.SortFunc(got, func(a, b key.EndpointID) int { return a.Compare(b) })
		if slices.Equal(got, want) {
			return
		}
		select {
		case <-ctx.Done():
			t.Fatalf("%s roster is %v, want %v", c.Name(), short(got), short(want))
		case <-time.After(20 * time.Millisecond):
		}
	}
}

func short(ids []key.EndpointID) []string {
	out := make([]string, len(ids))
	for i, id := range ids {
		out[i] = id.Short()
	}
	return out
}

// TestNetworkSealedRotate checks post-compromise security: a member
// rotates its own leaf keys, the founder commits the rotation, and the
// channel keeps working across the epoch that results.
//
// It also checks the property the rotation had to not cost. A staged
// update used to make its proposer unremovable, because a commit
// carrying both an update and a remove for one leaf is invalid and the
// founder's sweep offered no way to leave the update behind. A member
// that rotated and was then kicked would have wedged every later commit
// on the channel. So the last thing this test does is kick the member
// that just rotated.
func TestNetworkSealedRotate(t *testing.T) {
	if testing.Short() {
		t.Skip("network test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	alice := newTestNode(t, ctx, "alice")
	bob := newTestNode(t, ctx, "bob")

	room, ticket, err := alice.Found(ctx, "#vault", nil)
	if err != nil {
		t.Fatal(err)
	}
	aliceEvents := events(t, room)
	bobRoom, err := bob.JoinTicket(ctx, ticket)
	if err != nil {
		t.Fatal(err)
	}
	bobEvents := events(t, bobRoom)
	await(t, ctx, aliceEvents, func(ev Event) bool {
		return ev.Kind == Joined && ev.From.ID == bob.ID()
	}, "alice seeing bob join")

	before := bobRoom.seal.epoch()
	key0 := leafEncryptionKey(t, bobRoom.seal)

	// Bob rotates. The proposal alone changes nothing: it is the
	// founder's commit that moves the epoch.
	if err := bobRoom.seal.rotate(ctx); err != nil {
		t.Fatal(err)
	}
	waitFor(t, ctx, func() bool { return room.seal.staged() > 0 }, "alice staging bob's rotation")
	if got := room.seal.epoch(); got != before {
		t.Fatalf("epoch moved to %d on a proposal alone", got)
	}
	if err := room.seal.flush(ctx); err != nil {
		t.Fatal(err)
	}
	waitFor(t, ctx, func() bool { return bobRoom.seal.epoch() > before }, "bob applying the rotation")

	// The leaf keys actually changed, which is the whole point: an
	// attacker holding bob's old state is now locked out of the
	// ratchet the group derives from.
	if key1 := leafEncryptionKey(t, bobRoom.seal); key1 == key0 {
		t.Fatal("bob's leaf encryption key did not change")
	}
	// Flushing again with nothing staged must not spend an epoch.
	after := room.seal.epoch()
	if err := room.seal.flush(ctx); err != nil {
		t.Fatal(err)
	}
	if got := room.seal.epoch(); got != after {
		t.Fatalf("an empty flush moved the epoch from %d to %d", after, got)
	}

	// The seal still works across the new epoch.
	if err := room.Say(ctx, "rotated"); err != nil {
		t.Fatal(err)
	}
	ev := await(t, ctx, bobEvents, ofKind(Message), "bob reading across the rotation")
	if ev.Text != "rotated" {
		t.Fatalf("bob got %q", ev.Text)
	}

	// And the member that rotated is still removable while its
	// rotation is still staged, which is the case that used to wedge
	// the channel: a commit cannot carry both an update and a remove
	// for one leaf, so the founder's sweep had to be able to leave the
	// update behind. Kicking before the flush is what tests that.
	if err := bobRoom.seal.rotate(ctx); err != nil {
		t.Fatal(err)
	}
	waitFor(t, ctx, func() bool { return room.seal.staged() > 0 }, "alice staging bob's second rotation")
	if err := room.Kick(ctx, bob.ID()); err != nil {
		t.Fatalf("kicking a member that rotated: %v", err)
	}
	waitFor(t, ctx, func() bool { return len(room.Members()) == 1 }, "the kick landing on alice's roster")
	wantRoster(t, ctx, room, alice.ID())
}

// leafEncryptionKey returns the encryption key of the node's own leaf.
func leafEncryptionKey(t *testing.T, s *sealed) string {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	leaf := s.group.Tree.Leaf(s.group.Index)
	if leaf == nil {
		t.Fatalf("no leaf at index %d", s.group.Index)
	}
	return string(leaf.EncryptionKey)
}

// waitFor polls until cond holds or ctx ends.
func waitFor(t *testing.T, ctx context.Context, cond func() bool, what string) {
	t.Helper()
	for {
		if cond() {
			return
		}
		select {
		case <-ctx.Done():
			t.Fatalf("timed out %s", what)
		case <-time.After(20 * time.Millisecond):
		}
	}
}

// TestApplyCommitGuardedByFounder asserts that every call to
// mls.Group.ApplyCommit in this package is preceded by the sentByFounder
// gate in sealed.commit.
//
// The gate is what keeps an external commit out. RFC 9420 lets a
// non-member holding a GroupInfo commit itself into a group and remove
// members in the same message, and mls skips its proposal-list
// validation on that path (group.go, the external arm of ApplyCommit).
// What stops it here is that sentByFounder refuses a sender type of
// anything but member, so a new_member_commit never reaches ApplyCommit
// at all. A second call site would reopen that quietly, so this test
// fails the build rather than trusting a comment to be read.
func TestApplyCommitGuardedByFounder(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	var found []string
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		b, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		for i, line := range strings.Split(string(b), "\n") {
			if strings.Contains(line, ".ApplyCommit(") {
				found = append(found, fmt.Sprintf("%s:%d", name, i+1))
			}
		}
	}
	if len(found) != 1 {
		t.Fatalf("ApplyCommit called from %v; it must be called only from sealed.commit, after sentByFounder", found)
	}
	if !strings.HasPrefix(found[0], "sealed.go:") {
		t.Fatalf("ApplyCommit called from %v, not sealed.go", found[0])
	}
}

// TestNetworkSealedResendAcrossEpoch checks that a line sealed in the
// epoch a commit ends still arrives. The copy sealed in the old epoch is
// never gossiped, which is the loss made certain rather than raced for:
// alice has moved on before it could reach her, as a member that applied
// the commit first would have. What she gets is bob's resend, once.
func TestNetworkSealedResendAcrossEpoch(t *testing.T) {
	if testing.Short() {
		t.Skip("network test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	alice := newTestNode(t, ctx, "alice")
	bob := newTestNode(t, ctx, "bob")
	room, ticket, err := alice.Found(ctx, "#vault", nil)
	if err != nil {
		t.Fatal(err)
	}
	aliceEvents := events(t, room)
	bobRoom, err := bob.JoinTicket(ctx, ticket)
	if err != nil {
		t.Fatal(err)
	}
	await(t, ctx, aliceEvents, func(ev Event) bool {
		return ev.Kind == Joined && ev.From.ID == bob.ID()
	}, "alice seeing bob join")
	before := room.seal.epoch()
	waitFor(t, ctx, func() bool { return bobRoom.seal.epoch() == before }, "bob reaching alice's epoch")

	lost, err := bobRoom.seal.seal(kindMessage, "across the commit", time.Now())
	if err != nil {
		t.Fatal(err)
	}

	// A rotation is a commit with nobody added, so the only thing the
	// epoch change does to the line is make it unreadable.
	if err := bobRoom.seal.rotate(ctx); err != nil {
		t.Fatal(err)
	}
	waitFor(t, ctx, func() bool { return room.seal.staged() > 0 }, "alice staging bob's rotation")
	if err := room.seal.flush(ctx); err != nil {
		t.Fatal(err)
	}
	if out, behind := room.seal.receive(lost); len(out) != 0 || behind {
		t.Fatalf("alice read a line from the epoch she left: %v, behind %v", out, behind)
	}

	ev := await(t, ctx, aliceEvents, ofKind(Message), "alice receiving bob's resent line")
	if ev.Text != "across the commit" || ev.From.ID != bob.ID() {
		t.Fatalf("alice got %q from %v", ev.Text, ev.From.ID.Short())
	}
	// Once: the next line alice reads is the next one bob says.
	if err := bobRoom.Say(ctx, "after"); err != nil {
		t.Fatal(err)
	}
	ev = await(t, ctx, aliceEvents, ofKind(Message), "alice receiving bob's next line")
	if ev.Text != "after" {
		t.Fatalf("alice got %q, want the line after the resend", ev.Text)
	}
}

// TestSealedResendIsShownOnce checks that a member drops a note it
// already has when the sender seals it again.
func TestSealedResendIsShownOnce(t *testing.T) {
	if testing.Short() {
		t.Skip("network test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

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

	messages := func(out []Event) (n int) {
		for _, ev := range out {
			if ev.Kind == Message && ev.Text == "once" {
				n++
			}
		}
		return n
	}
	first, err := bobRoom.seal.seal(kindMessage, "once", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if out, _ := room.seal.receive(first); messages(out) != 1 {
		t.Fatalf("first delivery produced %v, want the line", out)
	}
	bobRoom.seal.mu.Lock()
	again := bobRoom.seal.reseal(time.Now())
	bobRoom.seal.mu.Unlock()
	if len(again) == 0 {
		t.Fatal("bob's outbox is empty")
	}
	for _, b := range again {
		if out, _ := room.seal.receive(b); messages(out) != 0 {
			t.Fatalf("the resent line was shown again: %v", out)
		}
	}
}

// TestSealedDropsControlCharacters checks that a sealed channel holds
// its members to the rule a public one does: a sender will not seal a
// line break, and a member drops a note from one that did.
func TestSealedDropsControlCharacters(t *testing.T) {
	if testing.Short() {
		t.Skip("network test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

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

	if err := bobRoom.Say(ctx, "hi\r\nQUIT"); !errors.Is(err, ErrControl) {
		t.Errorf("Say with CRLF = %v, want %v", err, ErrControl)
	}
	plain, err := postcard.Marshal(note{Version: noteVersion, Kind: uint8(kindMessage), Seq: bob.nextSeq(), Time: time.Now().UnixMilli(), Nick: "bob", Text: "hi\r\nQUIT"})
	if err != nil {
		t.Fatal(err)
	}
	bobRoom.seal.mu.Lock()
	b, err := bobRoom.seal.protect(plain)
	bobRoom.seal.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	out, _ := room.seal.receive(b)
	for _, ev := range out {
		if ev.Kind == Message {
			t.Errorf("a sealed line with CRLF was shown: %q", ev.Text)
		}
	}
}

func TestRecentAdd(t *testing.T) {
	full := make(recent, 0, maxSeen)
	for i := range maxSeen {
		full = append(full, uint64(100+i))
	}
	tests := []struct {
		name string
		r    recent
		seq  uint64
		want bool
	}{
		{"empty", nil, 5, true},
		{"new", recent{1, 2}, 3, true},
		{"repeat", recent{1, 2, 3}, 2, false},
		{"reordered", recent{1, 3}, 2, true},
		{"full, newer", full, 1000, true},
		{"full, within", full, 100 + maxSeen/2, false},
		{"full, older than all", full, 50, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := slices.Clone(tt.r)
			if got := r.add(tt.seq); got != tt.want {
				t.Fatalf("add(%d) = %v, want %v", tt.seq, got, tt.want)
			}
			if len(r) > maxSeen {
				t.Fatalf("recent grew to %d, past %d", len(r), maxSeen)
			}
			if !slices.IsSorted(r) {
				t.Fatalf("recent is out of order: %v", r)
			}
			if again := r.add(tt.seq); again {
				t.Fatalf("add(%d) accepted twice", tt.seq)
			}
		})
	}
}
