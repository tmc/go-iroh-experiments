package irciroh

import (
	"context"
	"testing"
	"time"

	"github.com/tmc/go-iroh/gossip"
	"github.com/tmc/go-iroh/key"
)

// TestOwnStatementsFollowTheSameRule checks that a node orders what it
// says itself - a topic, a mode, a rank - by the rule it orders
// everybody else's by. It applied its own unconditionally, stamped with
// its clock after the broadcast rather than the time the envelope
// carries, so it could keep a statement the rest of the channel had
// ordered before somebody else's, and disagree with them for good.
func TestOwnStatementsFollowTheSameRule(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	n := newTestNode(t, ctx, "self")
	later := time.Now().Add(time.Minute)

	t.Run("topic after a later one", func(t *testing.T) {
		c, err := n.Join(ctx, "#topic1", nil)
		if err != nil {
			t.Fatal(err)
		}
		peer := newKey(t)
		e, err := sign(peer, c.domain(), kindTopic, 1, "peer", "theirs")
		if err != nil {
			t.Fatal(err)
		}
		e.Time = later.UnixMilli()
		c.handle(gossip.Event{Kind: gossip.Received, Content: resignIn(t, peer, c.domain(), e)})
		if err := c.SetTopic(ctx, "mine"); err != nil {
			t.Fatal(err)
		}
		if got, _, _, _ := c.Topic(); got != "theirs" {
			t.Errorf("topic = %q; the channel kept %q, which was said later", got, "theirs")
		}
	})

	t.Run("topic tied with a higher id", func(t *testing.T) {
		c, err := n.Join(ctx, "#topic2", nil)
		if err != nil {
			t.Fatal(err)
		}
		if err := c.SetTopic(ctx, "mine"); err != nil {
			t.Fatal(err)
		}
		_, _, at, _ := c.Topic()
		// Same millisecond, higher id: every other member takes the
		// peer's, whichever order the two arrive in.
		peer := higherKey(t, n.ID())
		e, err := sign(peer, c.domain(), kindTopic, 1, "peer", "theirs")
		if err != nil {
			t.Fatal(err)
		}
		e.Time = at.UnixMilli()
		c.handle(gossip.Event{Kind: gossip.Received, Content: resignIn(t, peer, c.domain(), e)})
		if got, _, _, _ := c.Topic(); got != "theirs" {
			t.Errorf("topic = %q; a tie goes to the higher id, %q", got, "theirs")
		}
	})

	t.Run("mode after a later one", func(t *testing.T) {
		c, _, err := n.Found(ctx, "#mode", nil)
		if err != nil {
			t.Fatal(err)
		}
		c.mu.Lock()
		c.moderated, c.modeAt, c.modeBy = true, later, newKey(t).Public().EndpointID()
		c.mu.Unlock()
		if err := c.Moderate(ctx, false); err != nil {
			t.Fatal(err)
		}
		c.mu.Lock()
		on := c.moderated
		c.mu.Unlock()
		if !on {
			t.Error("Moderate overrode a mode said later")
		}
	})

	t.Run("rank after a later one", func(t *testing.T) {
		c, _, err := n.Found(ctx, "#rank", nil)
		if err != nil {
			t.Fatal(err)
		}
		id := newKey(t).Public().EndpointID()
		c.mu.Lock()
		c.touch(id, "member", time.Now())
		m := c.members[id]
		m.rank, m.rankAt, m.rankBy = Voiced, later, n.ID()
		c.mu.Unlock()
		if err := c.Grant(ctx, id, Ordinary); err != nil {
			t.Fatal(err)
		}
		c.mu.Lock()
		r := c.members[id].rank
		c.mu.Unlock()
		if r != Voiced {
			t.Errorf("rank = %v; Grant overrode a grant said later", r)
		}
	})
}

// resignIn signs an envelope whose fields a test has changed against
// domain.
func resignIn(t *testing.T, sk key.SecretKey, domain [32]byte, e envelope) []byte {
	t.Helper()
	msg, err := e.signed(domain)
	if err != nil {
		t.Fatal(err)
	}
	e.Sig = sk.Sign(msg).Bytes()
	b, err := e.encode()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// higherKey returns a key whose endpoint id sorts after id.
func higherKey(t *testing.T, id key.EndpointID) key.SecretKey {
	t.Helper()
	for {
		sk := newKey(t)
		if sk.Public().EndpointID().Compare(id) > 0 {
			return sk
		}
	}
}
