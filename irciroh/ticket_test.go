package irciroh

import (
	"errors"
	"net/netip"
	"strings"
	"testing"

	"github.com/tmc/go-iroh/netaddr"
)

func testAddr(t *testing.T, seed byte, port uint16) netaddr.EndpointAddr {
	t.Helper()
	id := testKey(t, seed).Public().EndpointID()
	return netaddr.NewEndpointAddr(id).WithIP(netip.AddrPortFrom(netip.IPv6Loopback(), port))
}

func TestTicketRoundTrip(t *testing.T) {
	tests := []struct {
		name string
		in   Ticket
	}{
		{"public", Ticket{Channel: "#go"}},
		{"peers", Ticket{Channel: "#go", Peers: []netaddr.EndpointAddr{testAddr(t, 1, 4001), testAddr(t, 2, 4002)}}},
		{"secret", Ticket{Channel: "#secret", Secret: []byte("hunter2"), Peers: []netaddr.EndpointAddr{testAddr(t, 3, 4003)}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := tt.in.String()
			if !strings.HasPrefix(s, TicketKind) {
				t.Fatalf("ticket %q does not start with %q", s, TicketKind)
			}
			got, err := ParseTicket(s)
			if err != nil {
				t.Fatal(err)
			}
			if got.Channel != tt.in.Channel || string(got.Secret) != string(tt.in.Secret) {
				t.Fatalf("got channel %q secret %q", got.Channel, got.Secret)
			}
			if len(got.Peers) != len(tt.in.Peers) {
				t.Fatalf("got %d peers, want %d", len(got.Peers), len(tt.in.Peers))
			}
			for i, p := range got.Peers {
				if p.String() != tt.in.Peers[i].String() {
					t.Errorf("peer %d = %v, want %v", i, p, tt.in.Peers[i])
				}
			}
		})
	}
}

func TestParseTicketErrors(t *testing.T) {
	good := Ticket{Channel: "#go"}.String()
	tests := []struct {
		name string
		in   string
	}{
		{"empty", ""},
		{"wrong prefix", "endpoint" + strings.TrimPrefix(good, TicketKind)},
		{"not base32", TicketKind + "!!!!"},
		{"truncated", good[:len(good)-4]},
		{"not a channel", Ticket{Channel: "go"}.String()},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := ParseTicket(tt.in); !errors.Is(err, ErrTicket) {
				t.Fatalf("ParseTicket = %v, want %v", err, ErrTicket)
			}
		})
	}
}

func TestTopicID(t *testing.T) {
	base := TopicID("#go", nil)
	if got := TopicID("#GO", nil); got != base {
		t.Error("topic id is not case-insensitive")
	}
	if got := TopicID("#go", []byte("s")); got == base {
		t.Error("secret does not change the topic id")
	}
	if got := TopicID("#golang", nil); got == base {
		t.Error("different channels share a topic id")
	}
}

func TestCheckChannel(t *testing.T) {
	tests := []struct {
		in   string
		want string
		ok   bool
	}{
		{"#go", "#go", true},
		{"#Go-Nuts", "#go-nuts", true},
		{"go", "", false},
		{"#", "", false},
		{"", "", false},
		{"#a b", "", false},
		{"#a,b", "", false},
		{"#a\x07b", "", false},
		{"#a\x7fb", "", false},
		{"#a\u0085b", "", false},
		{"#a\r\nb", "", false},
		{"#a/b", "", false},
		{"#../etc", "", false},
		{"#a\\b", "", false},
		{"#.", "", false},
		{"#..", "", false},
		{"#...", "#...", true},
		{"#.hidden", "#.hidden", true},
		{"#[x]", "#{x}", true},
		{"#é", "#é", true},
		{"#" + strings.Repeat("a", 60), "", false},
	}
	for _, tt := range tests {
		got, err := checkChannel(tt.in)
		if tt.ok {
			if err != nil {
				t.Errorf("checkChannel(%q) = %v", tt.in, err)
			} else if got != tt.want {
				t.Errorf("checkChannel(%q) = %q, want %q", tt.in, got, tt.want)
			}
			continue
		}
		if !errors.Is(err, ErrChannelName) {
			t.Errorf("checkChannel(%q) error = %v, want %v", tt.in, err, ErrChannelName)
		}
	}
}

func TestTicketAddrKeepsIPsOnlyWithoutARelay(t *testing.T) {
	id := testKey(t, 9).Public().EndpointID()
	ip4 := netip.MustParseAddrPort("203.0.113.7:41000")
	ip6 := netip.MustParseAddrPort("[2001:db8::1]:41000")
	relay, err := netaddr.ParseRelayURL("https://relay.example./")
	if err != nil {
		t.Fatal(err)
	}

	// With a relay, the addresses a peer was discovered at stay out of
	// the ticket: the relay reaches it and the direct path is
	// negotiated from there, so carrying them only tells everyone the
	// ticket ever reaches where its minter lives.
	full := netaddr.NewEndpointAddr(id).WithIP(ip4).WithIP(ip6).WithRelayURL(relay)
	got := ticketAddr(full)
	if ips := got.IPAddrs(); len(ips) != 0 {
		t.Errorf("ticket carries the minter's addresses %v", ips)
	}
	if urls := got.RelayURLs(); len(urls) != 1 || urls[0] != relay {
		t.Errorf("RelayURLs() = %v, want [%v]", urls, relay)
	}

	// Without one they are the only way to be reached, and dropping
	// them would make the ticket useless rather than private.
	bare := netaddr.NewEndpointAddr(id).WithIP(ip4)
	if ips := ticketAddr(bare).IPAddrs(); len(ips) != 1 || ips[0] != ip4 {
		t.Errorf("IPAddrs() = %v, want [%v]", ips, ip4)
	}
}
