package irciroh

import (
	"bytes"
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/tmc/go-iroh-experiments/mlsiroh"
	"github.com/tmc/go-iroh/gossip"
	"github.com/tmc/go-iroh/iroh"
	"github.com/tmc/go-iroh/key"
	"github.com/tmc/mls"
)

// TestNetworkSealedObserver is the holder of a leaked ticket: it reaches
// the topic and receives every byte a member does, but never joins the
// group. The question is what those bytes say.
//
// It watches the three kinds of message a sealed channel sends: a line,
// a rotation, which is a proposal, and an admission, which is a commit
// that adds a member. The line must not disclose what was said, and the
// proposal and the commit must not disclose who is in the channel: the
// endpoint ids of the member rotating and the member admitted are both
// in the handshake's content, so finding either on the wire means the
// handshake was sent in the clear.
func TestNetworkSealedObserver(t *testing.T) {
	if testing.Short() {
		t.Skip("network test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	alice := newTestNode(t, ctx, "alice")
	bob := newTestNode(t, ctx, "bob")
	carol := newTestNode(t, ctx, "carol")
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

	// Join the topic on the ticket alone, without joining the group.
	ep, err := iroh.Bind(ctx, iroh.WithBindAddr(netip.AddrPortFrom(netip.IPv6Loopback(), 0)))
	if err != nil {
		t.Fatal(err)
	}
	g := gossip.NewGossip(ep)
	router, err := iroh.NewRouter(ep, map[string]iroh.ProtocolHandler{gossip.ALPN: g.Handler()}, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = router.Shutdown(ctx)
		g.Shutdown(ctx)
		_ = ep.Shutdown(ctx)
	})
	sub, err := g.SubscribeAndJoin(ctx, SealedTopicID(ticket.Channel, ticket.Founder, ticket.Secret), ticket.Peers)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sub.Close() })
	got := make(chan []byte, 256)
	go func() {
		for ev, err := range sub.Events() {
			if err == nil && ev.Kind == gossip.Received {
				got <- ev.Content
			}
		}
	}()
	waitFor(t, ctx, func() bool { return len(sub.Neighbors()) > 0 }, "the observer reaching the swarm")

	const secret = "the eagle has landed"
	if err := room.Say(ctx, secret); err != nil {
		t.Fatal(err)
	}
	if err := bobRoom.seal.rotate(ctx); err != nil {
		t.Fatal(err)
	}
	waitFor(t, ctx, func() bool { return room.seal.staged() > 0 }, "alice staging bob's rotation")
	if err := room.seal.flush(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := carol.JoinTicket(ctx, ticket); err != nil {
		t.Fatal(err)
	}
	if err := room.Say(ctx, secret); err != nil {
		t.Fatal(err)
	}

	// The control: an endpoint's key package, in the clear, names the
	// endpoint in the form this scan looks for. Without it a scan that
	// found nothing would prove nothing.
	control := key.NewSecretKey([32]byte{1})
	c, err := mlsiroh.NewClient(control, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	kp, err := mls.Marshal(&mls.Message{Version: mls.Version10, WireFormat: mls.WireFormatKeyPackage, KeyPackage: c.KeyPackage})
	if err != nil {
		t.Fatal(err)
	}
	if !named(kp, control.Public().EndpointID()) {
		t.Fatal("a key package in the clear does not name its endpoint; the scan is vacuous")
	}

	// Collect until both handshakes have gone by: two commits, one for
	// the rotation and one for carol, and bob's proposal.
	count := make(map[mls.ContentType]int)
	var n int
	deadline := time.After(10 * time.Second)
collect:
	for count[mls.ContentTypeCommit] < 2 || count[mls.ContentTypeProposal] < 1 {
		select {
		case b := <-got:
			n++
			var m mls.Message
			if err := mls.Unmarshal(b, &m); err != nil {
				t.Errorf("payload %d is not an MLS message: %v", n, err)
				continue
			}
			var ct mls.ContentType
			switch {
			case m.PrivateMessage != nil:
				ct = m.PrivateMessage.ContentType
			case m.PublicMessage != nil:
				ct = m.PublicMessage.Content.ContentType
				t.Errorf("payload %d, a %v, is a PublicMessage, readable without the group's keys", n, ct)
			default:
				t.Errorf("payload %d is a %v, not a group message", n, m.WireFormat)
				continue
			}
			count[ct]++
			if bytes.Contains(b, []byte(secret)) {
				t.Errorf("payload %d carries plaintext %q", n, secret)
			}
			for _, who := range []*Node{bob, carol} {
				if named(b, who.ID()) {
					t.Errorf("payload %d, a %v, names %s's endpoint", n, ct, who.Nick())
				}
			}
		case <-deadline:
			break collect
		}
	}
	if count[mls.ContentTypeCommit] < 2 {
		t.Errorf("observed %d commits, want 2; the admission was never on the wire", count[mls.ContentTypeCommit])
	}
	if count[mls.ContentTypeProposal] < 1 {
		t.Error("observed no proposal; the rotation was never on the wire")
	}
	t.Logf("%d payloads observed: %d lines, %d proposals, %d commits",
		n, count[mls.ContentTypeApplication], count[mls.ContentTypeProposal], count[mls.ContentTypeCommit])
}

// named reports whether b holds id's key bytes, which is how an mlsiroh
// credential names an endpoint.
func named(b []byte, id key.EndpointID) bool {
	k := id.Bytes()
	return bytes.Contains(b, k[:])
}
