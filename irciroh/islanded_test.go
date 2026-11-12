package irciroh

import (
	"context"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/tmc/go-iroh/key"
	"github.com/tmc/go-iroh/netaddr"
)

// TestATicketReachesAnIslandedChannel holds what a ticket is for on a
// channel this node is already on. A public channel's ticket carries
// nothing but bootstrap peers: the topic comes from the name, so the
// peers are the entire content. A node on the right topic with no
// neighbours - a fleet that started together and found nobody - is
// exactly who is handed one, and dropping them made the join report
// success and do nothing.
func TestATicketReachesAnIslandedChannel(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	alice := newTestNode(t, ctx, "alice")
	bob := newTestNode(t, ctx, "bob")

	// Both join #island by name, with no way to find each other: no
	// rendezvous, no bootstrap peer. This is the island.
	ach, err := alice.JoinTicket(ctx, Ticket{Channel: "#island"})
	if err != nil {
		t.Fatal(err)
	}
	bch, err := bob.JoinTicket(ctx, Ticket{Channel: "#island"})
	if err != nil {
		t.Fatal(err)
	}
	if n := len(bch.topic.Neighbors()); n != 0 {
		t.Fatalf("bob found %d neighbours with nothing to find them by", n)
	}

	// Somebody hands bob a ticket naming alice, which is what a person
	// does when they see a node alone in a room.
	got, err := bob.JoinTicket(ctx, Ticket{Channel: "#island", Peers: []netaddr.EndpointAddr{alice.Addr()}})
	if err != nil {
		t.Fatalf("joining with a ticket for the channel bob is on: %v", err)
	}
	if got != bch {
		t.Fatal("the join made a second channel of the same name")
	}

	deadline := time.Now().Add(30 * time.Second)
	for len(bch.topic.Neighbors()) == 0 {
		if time.Now().After(deadline) {
			t.Fatal("bob is still alone: the ticket's peers were dropped")
		}
		time.Sleep(50 * time.Millisecond)
	}
	if n := len(ach.topic.Neighbors()); n == 0 {
		t.Error("alice never saw bob arrive")
	}
}

// TestAMemberNeedNotBeANeighbor holds the distinction [Channel.Neighbors]
// exists for. Presence is epidemic, so a roster fills with endpoints
// this node has never exchanged a packet with and has no route to;
// neighbours are who it is actually meshed with. A reader that takes a
// name in the roster for a peer it can reach is reading the swarm and
// thinking it is reading this node's place in it, and that is the
// difference between a channel that is quiet and a channel this node
// has been cut out of.
func TestAMemberNeedNotBeANeighbor(t *testing.T) {
	if testing.Short() {
		t.Skip("network test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	alice, carol, bob := newTestNode(t, ctx, "alice"), newTestNode(t, ctx, "carol"), newTestNode(t, ctx, "bob")

	// A line: alice - carol - bob. Nobody bootstraps from alice but
	// carol, and nobody from carol but bob.
	if _, err := alice.Join(ctx, "#line", nil); err != nil {
		t.Fatal(err)
	}
	if _, err := carol.Join(ctx, "#line", []netaddr.EndpointAddr{alice.Addr()}); err != nil {
		t.Fatal(err)
	}
	bch, err := bob.Join(ctx, "#line", []netaddr.EndpointAddr{carol.Addr()})
	if err != nil {
		t.Fatal(err)
	}

	// Alice reaches bob's roster, which is what presence being
	// epidemic means.
	deadline := time.Now().Add(30 * time.Second)
	for !slices.ContainsFunc(bch.Members(), func(m Member) bool { return m.ID == alice.ID() }) {
		if time.Now().After(deadline) {
			t.Fatal("alice never reached bob's roster, so there is no roster to contrast")
		}
		time.Sleep(50 * time.Millisecond)
	}
	if slices.Contains(bch.Neighbors(), alice.ID()) {
		t.Skip("bob meshed with alice directly; the topology this measures did not hold")
	}
	if !slices.Contains(bch.Neighbors(), carol.ID()) {
		t.Errorf("bob's neighbours are %v, want the peer he bootstrapped from", bch.Neighbors())
	}
}

// TestGossipRelaysWhatThisNodeCannotRead holds the mechanism the
// [Channel.Unverified] doc turns on. The tempting story about a zero is
// that a node refuses to pass on what it cannot verify, so an
// unreadable peer is only ever seen by whoever is meshed with it
// directly. That is not what happens: gossip forwards a swarm-scoped
// message as it arrives, before anything in this package runs and with
// no way for a verification result to reach it. The difference decides
// what a zero is evidence of, so it is held here rather than described.
func TestGossipRelaysWhatThisNodeCannotRead(t *testing.T) {
	if testing.Short() {
		t.Skip("network test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	alice, carol, bob := newTestNode(t, ctx, "alice"), newTestNode(t, ctx, "carol"), newTestNode(t, ctx, "bob")

	ach, err := alice.Join(ctx, "#relay", nil)
	if err != nil {
		t.Fatal(err)
	}
	cch, err := carol.Join(ctx, "#relay", []netaddr.EndpointAddr{alice.Addr()})
	if err != nil {
		t.Fatal(err)
	}
	bch, err := bob.Join(ctx, "#relay", []netaddr.EndpointAddr{carol.Addr()})
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(30 * time.Second)
	for len(bch.Neighbors()) == 0 {
		if time.Now().After(deadline) {
			t.Fatal("bob never meshed with anybody")
		}
		time.Sleep(50 * time.Millisecond)
	}
	if slices.Contains(bch.Neighbors(), alice.ID()) {
		t.Skip("bob meshed with alice directly; the relay this measures did not happen")
	}

	// Alice broadcasts something no node on this channel can decode,
	// which is what a peer signing by another rule looks like from
	// here. It is swarm-scoped, like everything the channel says.
	bev := events(t, bch)
	junk := []byte("not an envelope, and not signed by anybody")
	for range 5 {
		if err := ach.topic.Broadcast(ctx, junk); err != nil {
			t.Fatal(err)
		}
		junk = append(junk, '.')
	}
	for bch.Unverified() == 0 {
		if time.Now().After(deadline) {
			t.Fatalf("bob counted nothing from a peer he is not meshed with; his neighbours are %v", bch.Neighbors())
		}
		time.Sleep(50 * time.Millisecond)
	}

	// Carol counts too, which is what says the two do not disagree.
	// Carol is meshed with alice and bob is not, and if that decided
	// who counts then the neighbour set gossip handed each node would
	// be the whole story. It is not: the envelope reaches both, so a
	// zero beside a climbing count means the two are not on one
	// overlay rather than that they drew different neighbours. Carol
	// relays at the gossip layer before her own receive loop counts,
	// so bob can count first; she is given until the deadline.
	for cch.Unverified() == 0 {
		if time.Now().After(deadline) {
			t.Fatalf("carol is meshed with alice and counted nothing; bob, who is not, counted %d", bch.Unverified())
		}
		time.Sleep(50 * time.Millisecond)
	}

	// And bob says so, which is the half a count cannot say. Carol
	// handed bob the envelope and carol did not sign it, so a notice
	// reading as though a neighbor were signing differently would send
	// whoever read it to look at the one link that is working.
	ev := await(t, ctx, bev, func(ev Event) bool {
		return ev.Kind == Refused && strings.Contains(ev.Text, "did not verify")
	}, "bob's unverified notice")
	if strings.Contains(ev.Text, "from a neighbor") {
		t.Errorf("bob reported %q, but he is meshed with %v and alice signed it", ev.Text, bch.Neighbors())
	}
}

// TestASweepThatDropsSeveralSaysWhatIsLeft is the wiring, on a node
// with a real mesh under it. The neighbor count in the notice has to
// come from the overlay at the moment of the sweep and not from the
// member table, because the whole point of the sentence is that the
// two disagree: the members are going and the mesh is not.
func TestASweepThatDropsSeveralSaysWhatIsLeft(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	alice := newTestNode(t, ctx, "alice")
	bob := newTestNode(t, ctx, "bob")

	ach, err := alice.JoinTicket(ctx, Ticket{Channel: "#sweep"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := bob.JoinTicket(ctx, Ticket{Channel: "#sweep", Peers: []netaddr.EndpointAddr{alice.Addr()}}); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(30 * time.Second)
	for len(ach.topic.Neighbors()) == 0 {
		if time.Now().After(deadline) {
			t.Fatal("alice never meshed with bob")
		}
		time.Sleep(50 * time.Millisecond)
	}

	// Members that stopped announcing themselves a presence window ago.
	// Injected rather than run as nodes and killed, because what is
	// under test is one sweep taking several, and processes shut down
	// together land in the same sweep only by luck.
	aev := events(t, ach)
	stale := time.Now().Add(-2 * presenceTimeout)
	add := func(nicks ...string) {
		t.Helper()
		ach.mu.Lock()
		defer ach.mu.Unlock()
		for _, nick := range nicks {
			sk, err := key.GenerateSecretKey()
			if err != nil {
				t.Fatal(err)
			}
			id, err := key.NewEndpointID(sk.Public().Bytes())
			if err != nil {
				t.Fatal(err)
			}
			ach.members[id] = &member{nick: nick, seen: stale}
			ach.order = append(ach.order, id)
		}
	}

	// One member going is a member going, and saying anything else
	// about it would put the notice in front of a reader every time
	// anybody anywhere closed a client.
	add("alone")
	await(t, ctx, aev, ofKind(Parted), "the lone timeout")
	select {
	case ev := <-aev:
		if ev.Kind == Split {
			t.Fatalf("one timeout reported as a split: %q", ev.Text)
		}
	case <-time.After(10 * presenceSweep):
	}

	add("gone1", "gone2")

	ev := await(t, ctx, aev, ofKind(Split), "alice's split notice")
	want := "2 members timed out together; this node has 1 neighbor"
	if ev.Text != want {
		t.Fatalf("split notice = %q, want %q", ev.Text, want)
	}
	if !ev.From.ID.IsZero() {
		t.Errorf("split attributed to %v, want nobody", ev.From.ID)
	}
}
