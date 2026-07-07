package main

import (
	"net/netip"
	"testing"
)

func TestAddressClassification(t *testing.T) {
	tests := []struct {
		ip        string
		family    string
		scope     string
		tailscale bool
	}{
		{"127.0.0.1", "ipv4", "loopback", false},
		{"100.123.178.44", "ipv4", "cgnat", true},
		{"fd7a:115c:a1e0::1", "ipv6", "private", true},
		{"fe80::1", "ipv6", "link-local", false},
	}
	for _, tt := range tests {
		ip := netip.MustParseAddr(tt.ip)
		if got := family(ip); got != tt.family {
			t.Fatalf("family(%s) = %q, want %q", tt.ip, got, tt.family)
		}
		if got := scope(ip); got != tt.scope {
			t.Fatalf("scope(%s) = %q, want %q", tt.ip, got, tt.scope)
		}
		if got := isTailscale(ip); got != tt.tailscale {
			t.Fatalf("isTailscale(%s) = %t, want %t", tt.ip, got, tt.tailscale)
		}
	}
}
