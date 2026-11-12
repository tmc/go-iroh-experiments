package irciroh

import (
	"context"
	"testing"
	"time"

	"github.com/tmc/go-iroh/netaddr"
	"github.com/tmc/mls"
)

// TestNetworkSealedMemberTicket checks that a ticket minted by a member
// who is not the founder lets the next member in. Only the founder
// admits, so such a ticket has to say where the founder is, not just
// where the member who minted it is.
func TestNetworkSealedMemberTicket(t *testing.T) {
	if testing.Short() {
		t.Skip("network test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	alice := newTestNode(t, ctx, "alice")
	bob := newTestNode(t, ctx, "bob")
	carol := newTestNode(t, ctx, "carol")

	room, ticket, err := alice.Found(ctx, "#relay", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := bob.JoinTicket(ctx, ticket); err != nil {
		t.Fatal(err)
	}
	fromBob, err := bob.Ticket("#relay")
	if err != nil {
		t.Fatal(err)
	}
	if fromBob.Founder != alice.ID() {
		t.Fatalf("bob's ticket names founder %v, want alice", fromBob.Founder.Short())
	}
	carolRoom, err := carol.JoinTicket(ctx, fromBob)
	if err != nil {
		t.Fatalf("join on a member's ticket: %v", err)
	}
	wantRoster(t, ctx, carolRoom, alice.ID(), bob.ID(), carol.ID())
	wantRoster(t, ctx, room, alice.ID(), bob.ID(), carol.ID())
}

// TestInviteRateLimit checks that asking to join is charged to the
// endpoint that asks. A request that passes costs the founder a commit,
// so a ticket holder asking in a loop is a flood of commits.
func TestInviteRateLimit(t *testing.T) {
	n := &Node{invites: make(budgets)}
	a, b := testID(t), testID(t)
	now := time.Now()
	for i := range presenceBurst {
		if !n.mayAsk(a, now) {
			t.Fatalf("request %d of a burst of %d refused", i+1, presenceBurst)
		}
	}
	if n.mayAsk(a, now) {
		t.Fatal("request past the burst allowed")
	}
	if !n.mayAsk(b, now) {
		t.Fatal("another endpoint refused for the first one's requests")
	}
	if !n.mayAsk(a, now.Add(presenceRefill())) {
		t.Fatal("request refused after a refill")
	}
}

// TestNetworkInviteBusy checks that a founder serving as many invite
// streams as it will refuses the next one rather than queue it, and
// serves again once one finishes.
func TestNetworkInviteBusy(t *testing.T) {
	if testing.Short() {
		t.Skip("network test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	alice := newTestNode(t, ctx, "alice")
	bob := newTestNode(t, ctx, "bob")

	_, ticket, err := alice.Found(ctx, "#busy", nil)
	if err != nil {
		t.Fatal(err)
	}
	for range maxInviting {
		alice.inviting <- struct{}{}
	}
	if _, _, err := bob.ask(ctx, ticket, ticket.Peers); err == nil {
		t.Fatal("a founder with every invite slot taken served another")
	}
	for range maxInviting {
		<-alice.inviting
	}
	if _, err := bob.JoinTicket(ctx, ticket); err != nil {
		t.Fatalf("join once a slot is free: %v", err)
	}
}

// TestFoundConcurrent checks that founding one channel several times at
// once founds it once. Every call missed the channel, minted a group,
// and adopted it into the channel the first to register, so a later
// call replaced the group an earlier one had returned - and a member
// admitted into that group was left holding an epoch the founder no
// longer had.
func TestFoundConcurrent(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	alice := newTestNode(t, ctx, "alice")

	const n = 8
	type found struct {
		c   *Channel
		g   *mls.Group
		err error
	}
	out := make(chan found, n)
	for range n {
		go func() {
			c, _, err := alice.Found(ctx, "#once", nil)
			if err != nil {
				out <- found{err: err}
				return
			}
			c.seal.mu.Lock()
			g := c.seal.group
			c.seal.mu.Unlock()
			out <- found{c, g, nil}
		}()
	}
	var first found
	for i := range n {
		f := <-out
		if f.err != nil {
			t.Fatal(f.err)
		}
		if i == 0 {
			first = f
			continue
		}
		if f.c != first.c {
			t.Fatal("Found returned two channels for one name")
		}
		if f.g != first.g {
			t.Fatal("Found replaced the group of a channel it had already returned")
		}
	}
}

// TestJoinTicketConcurrent checks that joining one sealed channel several
// times at once asks the founder once. Every call found the channel
// unseated and asked, so the founder committed the same endpoint in and
// out again for each, and the joiner adopted whichever group its calls
// happened to finish with last - not necessarily the founder's latest.
func TestJoinTicketConcurrent(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	alice := newTestNode(t, ctx, "alice")
	bob := newTestNode(t, ctx, "bob")
	room, ticket, err := alice.Found(ctx, "#once", nil)
	if err != nil {
		t.Fatal(err)
	}
	ticket.Peers = []netaddr.EndpointAddr{alice.Addr()}

	const n = 4
	errs := make(chan error, n)
	for range n {
		go func() {
			_, err := bob.JoinTicket(ctx, ticket)
			errs <- err
		}()
	}
	for range n {
		if err := <-errs; err != nil {
			t.Fatal(err)
		}
	}
	if got := room.seal.epoch(); got != 1 {
		t.Errorf("founder at epoch %d after one member joined; want 1", got)
	}
	c, _ := bob.Channel("#once")
	if got, want := c.seal.epoch(), room.seal.epoch(); got != want {
		t.Errorf("joiner at epoch %d, founder at %d", got, want)
	}
}
