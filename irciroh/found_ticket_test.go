package irciroh

import (
	"context"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"

	"github.com/tmc/go-iroh/gossip"
	"github.com/tmc/go-iroh/iroh"
	"github.com/tmc/go-iroh/netaddr"
	"github.com/tmc/go-iroh/relay"
	"github.com/tmc/go-iroh/relayserver"
)

// TestFoundTicketAddresses checks the public API against a real local relay.
// A forwardable invitation must omit direct candidates when a relay can
// reach its founder, and retain them when they are the only available path.
func TestFoundTicketAddresses(t *testing.T) {
	if testing.Short() {
		t.Skip("local relay network test")
	}
	for _, mode := range []string{"relay", "direct"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			opts := []iroh.Option{
				iroh.WithBindAddr(netip.AddrPortFrom(netip.IPv6Loopback(), 0)),
			}
			var relayURL netaddr.RelayURL
			if mode == "relay" {
				server := httptest.NewServer(relayserver.New())
				t.Cleanup(server.Close)
				var err error
				relayURL, err = netaddr.ParseRelayURL(server.URL)
				if err != nil {
					t.Fatal(err)
				}
				opts = append(opts, iroh.WithRelayMode(relay.ModeCustom(relay.MapFromURLs(relayURL))))
			} else {
				opts = append(opts, iroh.WithRelayMode(relay.ModeDisabled()))
			}
			ep, err := iroh.Bind(ctx, opts...)
			if err != nil {
				t.Fatal(err)
			}
			g := gossip.NewGossip(ep)
			node, err := NewNode(ep, g, "alice")
			if err != nil {
				_ = ep.Shutdown(ctx)
				t.Fatal(err)
			}
			t.Cleanup(func() {
				stop, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				_ = node.Close()
				g.Shutdown(stop)
				_ = ep.Shutdown(stop)
			})
			if mode == "relay" {
				if err := ep.Online(ctx); err != nil {
					t.Fatal(err)
				}
			}
			if len(node.Addr().IPAddrs()) == 0 {
				t.Fatal("endpoint has no direct candidates to test")
			}
			// Repeat Found to cover its existing-channel return as well.
			for range 2 {
				_, ticket, err := node.Found(ctx, "#addresses", nil)
				if err != nil {
					t.Fatal(err)
				}
				decoded, err := ParseTicket(ticket.String())
				if err != nil {
					t.Fatal(err)
				}
				if len(decoded.Peers) != 1 || decoded.Peers[0].ID != node.ID() {
					t.Fatalf("invitation does not name its founder: %v", decoded.Peers)
				}
				addr := decoded.Peers[0]
				if mode == "relay" {
					if len(addr.IPAddrs()) != 0 {
						t.Fatalf("forwardable invitation exposes direct candidates: %v", addr.IPAddrs())
					}
					urls := addr.RelayURLs()
					if len(urls) != 1 || urls[0].String() != relayURL.String() {
						t.Fatalf("invitation relay = %v, want %v", urls, relayURL)
					}
				} else if len(addr.IPAddrs()) == 0 {
					t.Fatal("direct-only invitation has no usable address")
				}
			}
		})
	}
}
