package irciroh

import (
	"context"
	"net/netip"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tmc/go-iroh/gossip"
	"github.com/tmc/go-iroh/iroh"
	"github.com/tmc/go-iroh/netaddr"
)

// A stack is one node with everything under it: the endpoint, gossip,
// and a router serving every protocol this package has.
type stack struct {
	*Node
	ep     *iroh.Endpoint
	g      *gossip.Gossip
	router *iroh.Router
}

// newStack starts a stack on IPv6 loopback. Unlike newTestNode it
// leaves closing to the caller, so that a test can look at what is
// left running afterwards.
func newStack(t *testing.T, ctx context.Context, nick string, opts ...Option) *stack {
	t.Helper()
	ep, err := iroh.Bind(ctx, iroh.WithBindAddr(netip.AddrPortFrom(netip.IPv6Loopback(), 0)))
	if err != nil {
		t.Fatal(err)
	}
	g := gossip.NewGossip(ep)
	n, err := NewNode(ep, g, nick, append([]Option{WithStateDir(t.TempDir())}, opts...)...)
	if err != nil {
		t.Fatal(err)
	}
	router, err := iroh.NewRouter(ep, map[string]iroh.ProtocolHandler{
		gossip.ALPN: g.Handler(),
		ALPN:        n.Handler(),
		InviteALPN:  n.InviteHandler(),
		HistoryALPN: n.HistoryHandler(),
	}, nil)
	if err != nil {
		_ = ep.Shutdown(ctx)
		t.Fatal(err)
	}
	return &stack{n, ep, g, router}
}

// close closes the node and then everything under it.
func (s *stack) close() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = s.Node.Close()
	_ = s.router.Shutdown(ctx)
	s.g.Shutdown(ctx)
	_ = s.ep.Shutdown(ctx)
}

// settled waits for the goroutine count to return to base, and fails
// with the stacks of whatever is still running if it does not.
func settled(t *testing.T, base int, within time.Duration) {
	t.Helper()
	deadline := time.Now().Add(within)
	for {
		n := runtime.NumGoroutine()
		if n <= base {
			return
		}
		if time.Now().After(deadline) {
			buf := make([]byte, 1<<20)
			buf = buf[:runtime.Stack(buf, true)]
			var ours []string
			for _, g := range strings.Split(string(buf), "\n\n") {
				if strings.Contains(g, "irciroh") && !strings.Contains(g, "testing.tRunner") {
					ours = append(ours, g)
				}
			}
			t.Fatalf("%d goroutines, started with %d; these belong to irciroh:\n\n%s", n, base, strings.Join(ours, "\n\n"))
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// TestCloseLeavesNothingRunning exercises a public and a sealed channel,
// a private message and a recall, closes everything, and checks that
// every goroutine it started has gone.
func TestCloseLeavesNothingRunning(t *testing.T) {
	if testing.Short() {
		t.Skip("network test")
	}
	base := runtime.NumGoroutine()
	func() {
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()
		alice := newStack(t, ctx, "alice", WithHistory())
		bob := newStack(t, ctx, "bob", WithHistory())
		defer alice.close()
		defer bob.close()

		pub, err := alice.Join(ctx, "#leak", nil)
		if err != nil {
			t.Fatal(err)
		}
		if err := pub.Say(ctx, "before"); err != nil {
			t.Fatal(err)
		}
		bpub, err := bob.JoinTicket(ctx, Ticket{Channel: "#leak", Peers: []netaddr.EndpointAddr{alice.Addr()}})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := bpub.Recall(ctx, alice.Addr(), 10); err != nil {
			t.Fatal(err)
		}
		if err := bob.SetNick("robert"); err != nil {
			t.Fatal(err)
		}

		room, ticket, err := alice.Found(ctx, "#sealed", nil)
		if err != nil {
			t.Fatal(err)
		}
		broom, err := bob.JoinTicket(ctx, ticket)
		if err != nil {
			t.Fatal(err)
		}
		wantRoster(t, ctx, room, alice.ID(), bob.ID())
		if err := broom.Say(ctx, "sealed"); err != nil {
			t.Fatal(err)
		}
		if err := room.SetTopic(ctx, "topic"); err != nil {
			t.Fatal(err)
		}

		go func() {
			for range bob.Private() {
			}
		}()
		if err := alice.SendPrivate(ctx, bob.ID(), alice.PeerAddr(bob.ID()).WithAddrs(bob.Addr().Addrs()...), "psst"); err != nil {
			t.Fatal(err)
		}
		if err := bpub.Part(ctx, "bye"); err != nil {
			t.Fatal(err)
		}
	}()
	settled(t, base, 15*time.Second)
}

// TestCloseIsIdempotentAndConcurrent closes a node twice at once, while
// its channels are in use, and checks that nothing panics or hangs and
// that what is in flight returns.
func TestCloseIsIdempotentAndConcurrent(t *testing.T) {
	if testing.Short() {
		t.Skip("network test")
	}
	base := runtime.NumGoroutine()
	func() {
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()
		alice := newStack(t, ctx, "alice")
		bob := newStack(t, ctx, "bob")
		defer bob.close()
		defer alice.close()

		pub, err := alice.Join(ctx, "#busy", nil)
		if err != nil {
			t.Fatal(err)
		}
		room, ticket, err := alice.Found(ctx, "#sealed", nil)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := bob.JoinTicket(ctx, ticket); err != nil {
			t.Fatal(err)
		}

		var wg sync.WaitGroup
		for _, c := range []*Channel{pub, room} {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for i := 0; ; i++ {
					if c.Say(ctx, "busy") != nil {
						return
					}
					_ = c.SetTopic(ctx, "t")
					_ = alice.SetNick("a" + string(rune('a'+i%26)))
				}
			}()
		}
		wg.Add(2)
		go func() {
			defer wg.Done()
			for range 50 {
				c, err := alice.Join(ctx, "#late", nil)
				if err != nil {
					return
				}
				_ = c.Part(ctx, "")
			}
		}()
		go func() {
			defer wg.Done()
			_, _ = bob.JoinTicket(ctx, ticket)
		}()
		time.Sleep(200 * time.Millisecond)

		var closing sync.WaitGroup
		for range 2 {
			closing.Add(1)
			go func() {
				defer closing.Done()
				_ = alice.Node.Close()
			}()
		}
		closing.Wait()
		if err := alice.Node.Close(); err != nil {
			t.Errorf("third Close = %v", err)
		}

		done := make(chan struct{})
		go func() { wg.Wait(); close(done) }()
		select {
		case <-done:
		case <-ctx.Done():
			t.Fatal("operations in flight did not return after Close")
		}
		if err := pub.Say(ctx, "after"); err == nil {
			t.Error("Say on a closed node succeeded")
		}
		if _, err := alice.Join(ctx, "#after", nil); err == nil {
			t.Error("Join on a closed node succeeded")
		}
	}()
	settled(t, base, 15*time.Second)
}
