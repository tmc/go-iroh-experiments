package irciroh

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/tmc/go-iroh/key"
	"github.com/tmc/go-iroh/netaddr"
	"github.com/tmc/mls"
)

func rosterSize(t *testing.T, ctx context.Context, c *Channel, n int) {
	t.Helper()
	for {
		if len(c.Members()) == n {
			return
		}
		select {
		case <-ctx.Done():
			t.Fatalf("%s roster is %d, want %d", c.Name(), len(c.Members()), n)
		case <-time.After(100 * time.Millisecond):
		}
	}
}

// settle returns the founder's roster size after the channel has had a
// chance to churn: traffic keeps flowing for d, which is what tells a
// removed member it is behind.
func settle(t *testing.T, ctx context.Context, ac *Channel, d time.Duration) int {
	t.Helper()
	deadline := time.After(d)
	for {
		_ = ac.Say(ctx, "carry on")
		select {
		case <-deadline:
			return len(ac.Members())
		case <-time.After(500 * time.Millisecond):
		}
		if len(ac.Members()) == 2 {
			return 2
		}
	}
}

// TestKickIsDurable checks that a kick is a decision about an endpoint
// and not just about a leaf.
//
// Positive: a kicked member stays out even though it still holds the
// invite secret and keeps trying.
// Negative control: the SAME removal made without the ban flag - which
// is what a presence timeout does - readmits, proving the ledger and not
// some unrelated timing is what keeps the member out.
func TestKickIsDurable(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	run := func(t *testing.T, ban bool) int {
		alice := newTestNode(t, ctx, "alice")
		bob := newTestNode(t, ctx, "bob")
		ac, ticket, err := alice.Found(ctx, "#vault", nil)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := bob.JoinTicket(ctx, ticket); err != nil {
			t.Fatal(err)
		}
		bc, _ := bob.Channel("#vault")
		rosterSize(t, ctx, ac, 2)
		rosterSize(t, ctx, bc, 2)
		if ban {
			if err := ac.Kick(ctx, bob.ID()); err != nil {
				t.Fatal(err)
			}
		} else {
			if err := ac.seal.evict(ctx, bob.ID(), false); err != nil {
				t.Fatal(err)
			}
		}
		if got := len(ac.Members()); got != 1 {
			t.Fatalf("roster right after removal is %d, want 1", got)
		}
		return settle(t, ctx, ac, 20*time.Second)
	}

	t.Run("kick (ban)", func(t *testing.T) {
		if n := run(t, true); n != 1 {
			t.Errorf("kicked member came back: roster %d, want 1", n)
		} else {
			t.Log("PASS: kicked member stayed out for 20s of live traffic")
		}
	})
	t.Run("control: removal without ban", func(t *testing.T) {
		if n := run(t, false); n != 2 {
			t.Errorf("control did not readmit: roster %d, want 2 (the ledger is not the decisive predicate)", n)
		} else {
			t.Log("PASS: a non-ban removal still readmits, so the ban ledger is what is doing the work")
		}
	})
}

// TestKickSurvivesRestart checks the whole durable path: the founder
// comes back as itself, onto the same channel, still refusing the
// endpoint it kicked.
//
// Positive: after a restart the old ticket still names the channel and
// the banned endpoint is still refused.
// Negative control: a second endpoint holding the same ticket, never
// kicked, joins the restarted channel - so what stops the first one is
// the ban and not the restart.
func TestKickSurvivesRestart(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	dir := t.TempDir()
	aliceKey, err := key.GenerateSecretKey()
	if err != nil {
		t.Fatal(err)
	}
	bobKey, err := key.GenerateSecretKey()
	if err != nil {
		t.Fatal(err)
	}
	alice := newTestNodeAt(t, ctx, "alice", dir, &aliceKey)
	bob := newTestNodeAt(t, ctx, "bob", t.TempDir(), &bobKey)
	carol := newTestNode(t, ctx, "carol")

	ac, ticket, err := alice.Found(ctx, "#vault", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := bob.JoinTicket(ctx, ticket); err != nil {
		t.Fatal(err)
	}
	rosterSize(t, ctx, ac, 2)
	if err := ac.Kick(ctx, bob.ID()); err != nil {
		t.Fatal(err)
	}
	if err := alice.Close(); err != nil {
		t.Fatal(err)
	}

	// Alice comes back: same key, same state directory. A ticket's
	// peers are bootstrap hints, so the new run hands out its own
	// address; what has to be the same is the secret, because that is
	// the channel's identity now.
	alice2 := newTestNodeAt(t, ctx, "alice", dir, &aliceKey)
	ac2, ticket2, err := alice2.Found(ctx, "#vault", nil)
	if err != nil {
		t.Fatal(err)
	}
	if string(ticket2.Secret) != string(ticket.Secret) {
		t.Fatal("the restarted founder minted a new secret, so every ticket it handed out is void")
	}
	if ticket2.topic() != ticket.topic() {
		t.Fatal("same secret, different topic")
	}

	// The kicked operator restarts too, holding the same endpoint key
	// and the same ticket, and asks again.
	bob2 := newTestNodeAt(t, ctx, "bob", t.TempDir(), &bobKey)
	short, cancelShort := context.WithTimeout(ctx, 20*time.Second)
	_, err = bob2.JoinTicket(short, ticket2)
	cancelShort()
	if !errors.Is(err, ErrNotInvited) {
		t.Fatalf("the kicked endpoint rejoined after the founder restarted: %v", err)
	}
	t.Logf("PASS: kicked endpoint still refused across the restart: %v", err)

	// Control: the same ticket in hands that were never kicked. It
	// must work, or the refusal above proves nothing about the ban.
	if _, err := carol.JoinTicket(ctx, ticket2); err != nil {
		t.Fatalf("control: an unbanned holder of the ticket could not join: %v", err)
	}
	rosterSize(t, ctx, ac2, 2)
	t.Log("PASS: an unbanned holder of the same ticket still joins the restarted channel")
}

// TestResyncRateLimit checks that an unauthenticated epoch cannot buy
// more than one rejoin per interval.
//
// Positive: forged epochs arriving faster than the rejoin interval cost
// at most one founder commit per interval, and each one turned away is
// reported, since a steady run of those refusals is the only sign that
// someone is doing it on purpose.
// Negative control: the same node, genuinely behind, still recovers once
// the interval has passed - so the limit does not turn into a hang.
func TestResyncRateLimit(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	alice := newTestNode(t, ctx, "alice")
	bob := newTestNode(t, ctx, "bob")
	eve := newTestNode(t, ctx, "eve")

	ac, ticket, err := alice.Found(ctx, "#vault", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := bob.JoinTicket(ctx, ticket); err != nil {
		t.Fatal(err)
	}
	bc, _ := bob.Channel("#vault")
	rosterSize(t, ctx, ac, 2)
	rosterSize(t, ctx, bc, 2)
	// Both, because the forged epoch reaches both and either rejoining
	// costs the founder a commit.
	const every = 10 * time.Second
	ac.seal.setResyncEvery(every)
	bc.seal.setResyncEvery(every)

	// Eve needs the ticket to reach the topic at all now, so she is a
	// leaked invite rather than a passer-by. That is the remaining
	// attacker: the rate limit is what bounds her.
	topic, err := eve.g.SubscribeAndJoin(ctx, SealedTopicID("#vault", alice.ID(), ticket.Secret), ticket.Peers)
	if err != nil {
		t.Fatal(err)
	}
	gid := ac.seal.group.Context.GroupID
	forge := func(epoch uint64) []byte {
		b, err := mls.Marshal(&mls.Message{
			Version:    mls.Version10,
			WireFormat: mls.WireFormatPrivateMessage,
			PrivateMessage: &mls.PrivateMessage{
				GroupID: gid, Epoch: epoch,
				ContentType:         mls.ContentTypeApplication,
				EncryptedSenderData: []byte("garbage"),
				Ciphertext:          []byte("garbage"),
			},
		})
		if err != nil {
			t.Fatal(err)
		}
		return b
	}

	var mu sync.Mutex
	limited := 0
	for _, c := range []*Channel{ac, bc} {
		go func() {
			for ev, err := range c.Events() {
				if err == nil && ev.Kind == Refused && ev.Text == "rejoin rate-limited" {
					mu.Lock()
					limited++
					mu.Unlock()
				}
			}
		}()
	}

	base := ac.seal.epoch()
	// Positive: 5 distinct forged epochs inside one interval.
	for i := 0; i < 5; i++ {
		if err := topic.Broadcast(ctx, forge(base+100+uint64(i))); err != nil {
			t.Fatal(err)
		}
		time.Sleep(700 * time.Millisecond)
	}
	time.Sleep(3 * time.Second)
	after := ac.seal.epoch()
	t.Logf("5 forged epochs inside one %s interval: founder epoch %d -> %d", every, base, after)
	if after-base > 1 {
		t.Errorf("rate limit did not hold: %d commits from 5 forged payloads", after-base)
	}
	mu.Lock()
	n := limited
	mu.Unlock()
	if n == 0 {
		t.Error("forged epochs were turned away and nothing was reported")
	} else {
		t.Logf("PASS: %d rate-limited rejoins reported", n)
	}

	// Negative control: the same mechanism must still recover a member
	// that is genuinely behind once the interval has passed.
	if err := ac.seal.evict(ctx, bob.ID(), false); err != nil {
		t.Fatal(err)
	}
	if got := len(ac.Members()); got != 1 {
		t.Fatalf("roster after removal is %d, want 1", got)
	}
	if n := settle(t, ctx, ac, 40*time.Second); n != 2 {
		t.Errorf("control: a genuinely behind member did not recover: roster %d, want 2", n)
	} else {
		t.Log("PASS: genuine recovery still works after the interval")
	}
}

// TestRefusedEventReportsBan checks that the refusal is visible. A
// control that turns someone away silently leaves an operator with
// nothing to look at, so the ban path must emit a [Refused] event
// naming the endpoint.
func TestRefusedEventReportsBan(t *testing.T) {
	// Nothing is shortened: bob's first rejoin attempt is not rate
	// limited, and the refusal does not wait on presence.
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	alice := newTestNode(t, ctx, "alice")
	bob := newTestNode(t, ctx, "bob")
	ac, ticket, err := alice.Found(ctx, "#vault", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := bob.JoinTicket(ctx, ticket); err != nil {
		t.Fatal(err)
	}
	rosterSize(t, ctx, ac, 2)

	refused := make(chan Event, 1)
	go func() {
		for ev, err := range ac.Events() {
			if err == nil && ev.Kind == Refused {
				select {
				case refused <- ev:
				default:
				}
			}
		}
	}()

	if err := ac.Kick(ctx, bob.ID()); err != nil {
		t.Fatal(err)
	}
	// Bob is behind now and will come asking; every ask is refused.
	deadline := time.After(30 * time.Second)
	for {
		select {
		case ev := <-refused:
			if ev.From.ID != bob.ID() || ev.Text != "banned" {
				t.Fatalf("refused event is %v %q, want bob banned", ev.From.ID.Short(), ev.Text)
			}
			t.Logf("PASS: refusal is reported: %s %s", ev.From.ID.Short(), ev.Text)
			return
		case <-deadline:
			t.Fatal("a banned endpoint kept dialing and nothing was reported")
		case <-time.After(500 * time.Millisecond):
			_ = ac.Say(ctx, "carry on")
		}
	}
}

// TestKickIsReportedToTheFounder checks that the node that removes a
// member hears about it. A node never receives its own gossip, so the
// commit that carries a removal reaches every member except the one that
// made it; without emitting the removal locally the founder is the only
// participant whose roster changes silently, and a bridge in front of it
// never tells its client anything happened.
//
// The parting also says which kind of removal it was. A kick and a
// presence timeout leave the same hole in the tree, and only the node
// that acted knows the difference.
func TestKickIsReportedToTheFounder(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	alice := newTestNode(t, ctx, "alice")
	bob := newTestNode(t, ctx, "bob")
	ac, ticket, err := alice.Found(ctx, "#vault", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := bob.JoinTicket(ctx, ticket); err != nil {
		t.Fatal(err)
	}
	rosterSize(t, ctx, ac, 2)

	parted := make(chan Event, 4)
	go func() {
		for ev, err := range ac.Events() {
			if err == nil && ev.Kind == Parted {
				select {
				case parted <- ev:
				default:
				}
			}
		}
	}()

	if err := ac.Kick(ctx, bob.ID()); err != nil {
		t.Fatal(err)
	}
	select {
	case ev := <-parted:
		if ev.From.ID != bob.ID() {
			t.Fatalf("parting names %v, want bob", ev.From.ID.Short())
		}
		if ev.Text != "kicked" {
			t.Errorf("parting reads %q, want %q", ev.Text, "kicked")
		}
	case <-time.After(20 * time.Second):
		t.Fatal("the founder kicked a member and its own reader was never told")
	}
}

// TestFoundedChannelIsNotJoinedByName checks that a plain join of a
// channel this node founded is refused rather than answered with the
// public channel of the same name. The two have different topics, so
// the public one is readable by anyone who guesses the name; silently
// substituting it on a rejoin would be a downgrade the caller never
// asked for.
//
// Positive: a bare join of the founded name is refused with
// [ErrFounded], and founding again returns the sealed channel.
// Negative control: the same bare join on a name this node never
// founded succeeds, so what refuses is the founder secret and not the
// join path.
func TestFoundedChannelIsNotJoinedByName(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	dir := t.TempDir()
	k, err := key.GenerateSecretKey()
	if err != nil {
		t.Fatal(err)
	}
	alice := newTestNodeAt(t, ctx, "alice", dir, &k)
	if _, _, err := alice.Found(ctx, "#vault", nil); err != nil {
		t.Fatal(err)
	}
	if err := alice.Close(); err != nil {
		t.Fatal(err)
	}

	alice2 := newTestNodeAt(t, ctx, "alice", dir, &k)
	if _, err := alice2.Join(ctx, "#vault", nil); !errors.Is(err, ErrFounded) {
		t.Fatalf("Join(#vault) = %v, want %v", err, ErrFounded)
	}
	ch, _, err := alice2.Found(ctx, "#vault", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, sealed := ch.Founder(); !sealed {
		t.Fatal("re-founded #vault is not sealed")
	}
	if _, err := alice2.Join(ctx, "#lobby", nil); err != nil {
		t.Fatalf("Join(#lobby) = %v, want nil", err)
	}
}

// TestJoinIgnoresItsOwnAddress checks that a node handed its own
// address as a bootstrap peer joins anyway rather than waiting for the
// swarm.
//
// Waiting for the swarm means waiting for a neighbor, and a node cannot
// be its own neighbor. The address arrives this way in practice: a
// founder re-founding a channel after a restart finds the rendezvous
// record it published on the previous run.
//
// Positive: the join returns well inside a deadline it would otherwise
// run out.
// Negative control: the same join with a peer that is not this node
// waits until the caller's deadline, so what returns the first one is
// the filter and not a join that never waits.
func TestJoinIgnoresItsOwnAddress(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	n := newTestNode(t, ctx, "alice")
	self, cancelSelf := context.WithTimeout(ctx, 10*time.Second)
	defer cancelSelf()
	if _, err := n.JoinTicket(self, Ticket{Channel: "#hall", Peers: []netaddr.EndpointAddr{n.Addr()}}); err != nil {
		t.Fatalf("join with own address as peer: %v", err)
	}

	other := newTestNode(t, ctx, "bob")
	gone, cancelGone := context.WithTimeout(ctx, time.Second)
	defer cancelGone()
	if err := other.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := n.JoinTicket(gone, Ticket{Channel: "#void", Peers: []netaddr.EndpointAddr{other.Addr()}}); err == nil {
		t.Fatal("join with an unreachable peer did not wait for the swarm")
	}
}

// TestJoinOutlivesAStaleBootstrapPeer checks that a join whose only
// bootstrap address no longer answers still joins.
//
// A bootstrap address on a serverless network is a hint, and hints go
// stale: a rendezvous record outlives the run that published it. The
// wait for a neighbor is there so the first broadcast does not go
// nowhere, which is worth a bounded wait and not worth refusing a
// channel that is working.
//
// Positive: the join returns without error, and takes long enough to
// show it waited rather than skipped the wait.
func TestJoinOutlivesAStaleBootstrapPeer(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	n := newTestNode(t, ctx, "alice")
	gone := newTestNode(t, ctx, "bob")
	addr := gone.Addr()
	if err := gone.Close(); err != nil {
		t.Fatal(err)
	}

	start := time.Now()
	if _, err := n.JoinTicket(ctx, Ticket{Channel: "#hall", Peers: []netaddr.EndpointAddr{addr}}); err != nil {
		t.Fatalf("join with a stale bootstrap peer: %v", err)
	}
	if waited := time.Since(start); waited < joinTimeout {
		t.Fatalf("join returned after %v, want a wait of at least %v", waited, joinTimeout)
	}
}

// TestKickedMemberIsTold checks the kick from the kicked side. The
// member cannot follow the commit that removes it and the founder
// refuses to seat it again, so the channel is over for it: its event
// stream ends with it parting, the node forgets the channel, and Say
// fails. It used to stay on the channel for good, with the roster it
// had before the kick, saying things in an epoch nobody else was in.
func TestKickedMemberIsTold(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	alice := newTestNode(t, ctx, "alice")
	bob := newTestNode(t, ctx, "bob")
	ac, ticket, err := alice.Found(ctx, "#vault", nil)
	if err != nil {
		t.Fatal(err)
	}
	bc, err := bob.JoinTicket(ctx, ticket)
	if err != nil {
		t.Fatal(err)
	}
	rosterSize(t, ctx, bc, 2)
	if err := ac.Kick(ctx, bob.ID()); err != nil {
		t.Fatal(err)
	}
	ended := make(chan Event, 1)
	go func() {
		var last Event
		for ev := range bc.Events() {
			last = ev
		}
		ended <- last
	}()
	tick := time.NewTicker(50 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case last := <-ended:
			if last.Kind != Parted || last.From.ID != bob.ID() {
				t.Errorf("last event is %v from %v, want bob parting", last.Kind, last.From.ID.Short())
			}
			if _, ok := bob.Channel("#vault"); ok {
				t.Error("the kicked node still has the channel")
			}
			if err := bc.Say(ctx, "anyone?"); err == nil {
				t.Error("Say on the channel the node was kicked from succeeded")
			}
			if _, err := bob.JoinTicket(ctx, ticket); !errors.Is(err, ErrNotInvited) {
				t.Errorf("rejoin after the kick = %v, want ErrNotInvited", err)
			}
			return
		case <-tick.C:
			_ = ac.Say(ctx, "traffic")
		case <-ctx.Done():
			t.Fatalf("the kicked member is still on the channel, roster %d", len(bc.Members()))
		}
	}
}

// TestReadmittedMemberKnowsItsRank holds that a member the founder
// removed and then let back in agrees with everyone else about its own
// standing. The removal ends the membership its rank belonged to, so
// every other member forgets the rank; the removed member has to as
// well, or it goes on granting, kicking or speaking under +m with an
// authority nobody else honors. A rejoin that keeps the member's leaf
// in the same commit is not a removal, and keeps the rank everywhere.
func TestReadmittedMemberKnowsItsRank(t *testing.T) {
	tests := []struct {
		name   string
		remove func(ctx context.Context, room, bc *Channel, bob *Node) error
		want   Rank
	}{
		{"removed and readmitted", func(ctx context.Context, room, bc *Channel, bob *Node) error {
			return room.seal.evict(ctx, bob.ID(), false)
		}, Ordinary},
		{"reseated", func(ctx context.Context, room, bc *Channel, bob *Node) error {
			bc.resync()
			return nil
		}, Operator},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
			defer cancel()
			alice := newTestNode(t, ctx, "alice")
			bob := newTestNode(t, ctx, "bob")
			room, ticket, err := alice.Found(ctx, "#vault", nil)
			if err != nil {
				t.Fatal(err)
			}
			bc, err := bob.JoinTicket(ctx, ticket)
			if err != nil {
				t.Fatal(err)
			}
			wantRoster(t, ctx, room, alice.ID(), bob.ID())
			if err := room.Grant(ctx, bob.ID(), Operator); err != nil {
				t.Fatal(err)
			}
			waitFor(t, ctx, func() bool { return bc.Rank(bob.ID()) == Operator }, "bob hearing he is an operator")
			before := bc.seal.epoch()

			if err := tt.remove(ctx, room, bc, bob); err != nil {
				t.Fatal(err)
			}
			// Readmitted, or reseated: a later epoch, and on the
			// roster at both ends.
			waitFor(t, ctx, func() bool {
				return bc.seal.epoch() > before && len(bc.Members()) == 2 && len(room.Members()) == 2
			}, "bob back on the channel")
			waitFor(t, ctx, func() bool { return room.Rank(bob.ID()) == tt.want }, "alice's view of bob's rank")
			if got := bc.Rank(bob.ID()); got != tt.want {
				t.Errorf("bob thinks he is %v; alice says %v", got, room.Rank(bob.ID()))
			}
		})
	}
}
