package dtrain

import (
	"context"
	"net/netip"
	"reflect"
	"testing"
	"time"

	"github.com/tmc/go-iroh/gossip"
	"github.com/tmc/go-iroh/iroh"
	"github.com/tmc/go-iroh/netaddr"
)

func TestGroupMembershipConverges(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	const n = 3
	nodes := make([]testNode, n)
	for i := range nodes {
		nodes[i] = newTestNode(t, ctx)
		defer nodes[i].close(ctx)
	}

	groups := make([]*Group, n)
	var err error
	groups[0], err = JoinGroup(ctx, nodes[0].ep, nodes[0].gossip, "train", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer groups[0].Close()
	for i := 1; i < n; i++ {
		var bootstrap []netaddr.EndpointAddr
		for j := 0; j < i; j++ {
			bootstrap = append(bootstrap, nodes[j].addr())
		}
		groups[i], err = JoinGroup(ctx, nodes[i].ep, nodes[i].gossip, "train", bootstrap)
		if err != nil {
			t.Fatal(err)
		}
		defer groups[i].Close()
	}

	wantIDs := rankedIDs(groups[0].Members())
	if err := waitFor(ctx, func() bool {
		wantIDs = rankedIDs(groups[0].Members())
		if len(wantIDs) != n {
			return false
		}
		for _, g := range groups[1:] {
			if !reflect.DeepEqual(rankedIDs(g.Members()), wantIDs) {
				return false
			}
			if g.Rank() < 0 {
				return false
			}
		}
		return true
	}); err != nil {
		for i, g := range groups {
			t.Logf("group %d members: %v", i, rankedIDs(g.Members()))
		}
		t.Fatal(err)
	}

	if err := waitFor(ctx, func() bool {
		for _, g := range groups {
			if len(g.topic.Neighbors()) == 0 {
				return false
			}
		}
		return true
	}); err != nil {
		t.Fatal(err)
	}
}

type testNode struct {
	ep     *iroh.Endpoint
	gossip *gossip.Gossip
	dtrain *Handler
	router *iroh.Router
}

func newTestNode(t *testing.T, ctx context.Context) testNode {
	t.Helper()
	ep, err := iroh.Bind(ctx, iroh.WithBindAddr(netip.AddrPortFrom(netip.IPv6Loopback(), 0)))
	if err != nil {
		t.Fatal(err)
	}
	g := gossip.NewGossip(ep)
	router, err := iroh.NewRouter(ep, map[string]iroh.ProtocolHandler{
		gossip.ALPN: g.Handler(),
	}, nil)
	if err != nil {
		_ = ep.Shutdown(ctx)
		t.Fatal(err)
	}
	return testNode{ep: ep, gossip: g, router: router}
}

func (n testNode) addr() netaddr.EndpointAddr {
	return netaddr.NewEndpointAddr(n.ep.ID()).WithIP(n.ep.LocalAddr())
}

func (n testNode) close(ctx context.Context) {
	_ = n.router.Shutdown(ctx)
	n.gossip.Shutdown(ctx)
	_ = n.ep.Shutdown(ctx)
}

func rankedIDs(members []Member) []string {
	out := make([]string, len(members))
	for i, m := range members {
		if m.Rank != i {
			return nil
		}
		out[i] = m.ID.String()
	}
	return out
}

func waitFor(ctx context.Context, f func() bool) error {
	tick := time.NewTicker(25 * time.Millisecond)
	defer tick.Stop()
	for {
		if f() {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-tick.C:
		}
	}
}
