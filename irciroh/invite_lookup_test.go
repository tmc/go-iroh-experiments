package irciroh

import (
	"context"
	"errors"
	"iter"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tmc/go-iroh/dns"
	"github.com/tmc/go-iroh/gossip"
	"github.com/tmc/go-iroh/iroh"
	"github.com/tmc/go-iroh/key"
	"github.com/tmc/go-iroh/netaddr"
)

// TestInviteRefreshesFailedHints models a ticket whose founder has moved. The
// endpoint's dial hook rejects the stale path before any request can be sent;
// its real lookup service supplies the founder's current loopback address.
func TestInviteRefreshesFailedHints(t *testing.T) {
	for _, tt := range []struct {
		name        string
		stale       bool
		bare        bool
		refuse      bool
		wantDials   int32
		wantLookups int32
	}{
		{name: "stale hint", stale: true, wantDials: 2, wantLookups: 1},
		{name: "working hint", wantDials: 1},
		{name: "bare identity", bare: true, wantDials: 1, wantLookups: 1},
		{name: "refused admission", refuse: true, wantDials: 1},
	} {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			founder := newTestNode(t, ctx, "founder")
			var admissions atomic.Int32
			_, ticket, err := founder.Found(ctx, "#lookup", func(key.EndpointID) bool {
				admissions.Add(1)
				return !tt.refuse
			})
			if err != nil {
				t.Fatal(err)
			}
			current := founder.Addr()
			stale := netaddr.NewEndpointAddr(founder.ID()).WithIP(netip.MustParseAddrPort("[::1]:9"))
			var dials, lookups atomic.Int32
			deadlines := make(chan time.Time, 2)
			lookup := new(iroh.AddressLookupServices)
			lookup.AddResolver(iroh.AddressResolverFunc(func(ctx context.Context, id key.EndpointID) iter.Seq2[iroh.Item, error] {
				return func(yield func(iroh.Item, error) bool) {
					// Path actors also resolve asynchronously after a dial.
					// Count only lookup calls belonging to this admission.
					if ctx.Value(inviteLookupContextKey{}) == true {
						lookups.Add(1)
					}
					if id != founder.ID() {
						t.Errorf("lookup identity = %s, want %s", id, founder.ID())
					}
					yield(iroh.NewItem(dns.EndpointInfo{ID: id, Data: dns.NewEndpointData(current.Addrs()...)}, "test", nil), nil)
				}
			}))
			endpoint, err := iroh.Bind(ctx,
				iroh.WithBindAddr(netip.AddrPortFrom(netip.IPv6Loopback(), 0)),
				iroh.WithAddressLookup(lookup),
				iroh.WithHooks(inviteLookupHooks{before: func(ctx context.Context, addr netaddr.EndpointAddr, alpn string) error {
					dials.Add(1)
					deadline, _ := ctx.Deadline()
					deadlines <- deadline
					if addr.ID != founder.ID() || alpn != InviteALPN {
						t.Errorf("dial = %s %s, want founder invite", addr.ID, alpn)
					}
					if len(addr.IPAddrs()) == 1 && addr.IPAddrs()[0] == stale.IPAddrs()[0] {
						return errors.New("stale ticket path")
					}
					return ctx.Err()
				}}))
			if err != nil {
				t.Fatal(err)
			}
			g := gossip.NewGossip(endpoint)
			member, err := NewNode(endpoint, g, "member")
			if err != nil {
				endpoint.Shutdown(ctx)
				t.Fatal(err)
			}
			t.Cleanup(func() {
				member.Close()
				stop, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				g.Shutdown(stop)
				endpoint.Shutdown(stop)
			})
			hint := current
			if tt.stale {
				hint = stale
			} else if tt.bare {
				hint = netaddr.NewEndpointAddr(founder.ID())
			}
			requestCtx := context.WithValue(ctx, inviteLookupContextKey{}, true)
			_, _, err = member.ask(requestCtx, ticket, []netaddr.EndpointAddr{hint})
			if tt.refuse {
				if !errors.Is(err, ErrNotInvited) {
					t.Fatalf("refused admission = %v, want ErrNotInvited", err)
				}
			} else if err != nil {
				t.Fatal(err)
			}
			if got := dials.Load(); got != tt.wantDials {
				t.Errorf("dials = %d, want %d", got, tt.wantDials)
			}
			if got := lookups.Load(); got != tt.wantLookups {
				t.Errorf("lookups = %d, want %d", got, tt.wantLookups)
			}
			if got := admissions.Load(); got != 1 {
				t.Errorf("admissions = %d, want exactly one", got)
			}
			if tt.stale {
				first, second := <-deadlines, <-deadlines
				parent, _ := requestCtx.Deadline()
				if !first.Before(second) || !second.Equal(parent) {
					t.Errorf("dial deadlines = %v, %v; want a reserved first budget and unchanged parent %v", first, second, parent)
				}
			}
		})
	}
}

type inviteLookupHooks struct {
	before func(context.Context, netaddr.EndpointAddr, string) error
}

type inviteLookupContextKey struct{}

func (h inviteLookupHooks) BeforeConnect(ctx context.Context, addr netaddr.EndpointAddr, alpn string) error {
	return h.before(ctx, addr, alpn)
}

func (inviteLookupHooks) AfterHandshake(context.Context, *iroh.Conn) error { return nil }
