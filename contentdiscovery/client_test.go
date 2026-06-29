package contentdiscovery

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/tmc/go-iroh/blobs"
	"github.com/tmc/go-iroh/iroh"
	"github.com/tmc/go-iroh/key"
	"github.com/tmc/go-iroh/netaddr"
)

func TestClientTrackerRoundTrip(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	server, err := iroh.Bind(ctx, iroh.WithBindAddr(netip.AddrPortFrom(netip.IPv6Loopback(), 0)))
	if err != nil {
		t.Fatalf("bind server: %v", err)
	}
	store := NewStore(time.Hour)
	router, err := iroh.NewRouter(server, map[string]iroh.ProtocolHandler{
		ALPN: NewTrackerHandler(store),
	}, nil)
	if err != nil {
		t.Fatalf("new router: %v", err)
	}
	defer router.Shutdown(ctx)

	clientEP, err := iroh.Bind(ctx, iroh.WithBindAddr(netip.AddrPortFrom(netip.IPv6Loopback(), 0)))
	if err != nil {
		t.Fatalf("bind client: %v", err)
	}
	defer clientEP.Shutdown(ctx)

	secret := key.NewSecretKey([32]byte{1})
	content := blobs.RawHash(blobs.NewHash([]byte("content")))
	tracker := netaddr.NewEndpointAddr(server.ID()).WithIP(server.LocalAddr())
	client := NewClient(clientEP)
	if err := client.Announce(ctx, tracker, secret, content, AnnounceComplete); err != nil {
		t.Fatalf("Announce: %v", err)
	}
	got, err := client.Query(ctx, tracker, content, QueryFlags{Complete: true, Verified: true})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("Query returned %d announces, want 1", len(got))
	}
	if !got[0].Announce.Host.Equal(secret.Public().EndpointID()) {
		t.Fatalf("host = %s, want %s", got[0].Announce.Host, secret.Public().EndpointID())
	}
	if got[0].Announce.Content != content {
		t.Fatalf("content = %+v, want %+v", got[0].Announce.Content, content)
	}
}
