package enclaveiroh

import (
	"bytes"
	"context"
	"net"
	"strings"
	"testing"

	"github.com/tmc/go-iroh/key"
)

func TestFrameRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	in := hello{V: 1, Nonce: "abc", Mode: "mutual"}
	if err := writeFrame(&buf, in); err != nil {
		t.Fatalf("writeFrame: %v", err)
	}
	var out hello
	if err := readFrame(&buf, &out); err != nil {
		t.Fatalf("readFrame: %v", err)
	}
	if out != in {
		t.Fatalf("round trip = %+v, want %+v", out, in)
	}
}

func TestReadFrameRejectsOversizeHeader(t *testing.T) {
	// A length prefix past the cap must be refused before allocating.
	var buf bytes.Buffer
	buf.Write([]byte{0xff, 0xff, 0xff, 0xff}) // 4 GiB claimed
	if err := readFrame(&buf, &hello{}); err == nil || !strings.Contains(err.Error(), "frame too large") {
		t.Fatalf("readFrame oversize = %v, want a 'frame too large' error", err)
	}
}

func TestModeParseAndString(t *testing.T) {
	for _, m := range []Mode{ModeMutual, ModeProve, ModeVerify} {
		got, err := parseMode(m.String())
		if err != nil || got != m {
			t.Fatalf("parseMode(%q) = %v, %v; want %v", m.String(), got, err, m)
		}
	}
	if _, err := parseMode("bogus"); err == nil {
		t.Fatal("parseMode(bogus) = nil error, want error")
	}
}

// runPair runs both sides of a handshake over a net.Pipe and returns each
// side's result. dialerCfg drives the dialer, serverCfg the server.
func runPair(t *testing.T, dialerCfg, serverCfg HandshakeConfig) (dialerAtt, serverAtt *PeerAttestation, dialerErr, serverErr error) {
	t.Helper()
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	type res struct {
		att *PeerAttestation
		err error
	}
	done := make(chan res, 1)
	go func() {
		att, err := runHandshake(context.Background(), c2, false, dialerCfg.SelfID, "enclaveiroh/echo/1", serverCfg)
		done <- res{att, err}
	}()
	dialerAtt, dialerErr = runHandshake(context.Background(), c1, true, serverCfg.SelfID, "enclaveiroh/echo/1", dialerCfg)
	r := <-done
	return dialerAtt, r.att, dialerErr, r.err
}

func idOf(t *testing.T) key.EndpointID {
	t.Helper()
	sk, err := key.GenerateSecretKey()
	if err != nil {
		t.Fatalf("GenerateSecretKey: %v", err)
	}
	return sk.Public().EndpointID()
}

func TestHandshakeMutual(t *testing.T) {
	dialerID, serverID := idOf(t), idOf(t)
	dialerCfg := HandshakeConfig{SelfID: dialerID, Mode: ModeMutual, Signer: newFakeSigner(t), EphemeralKey: true}
	serverCfg := HandshakeConfig{SelfID: serverID, Mode: ModeMutual, Signer: newFakeSigner(t), EphemeralKey: true}

	dAtt, sAtt, dErr, sErr := runPair(t, dialerCfg, serverCfg)
	if dErr != nil || sErr != nil {
		t.Fatalf("handshake errors: dialer=%v server=%v", dErr, sErr)
	}
	if !dAtt.Attested || !sAtt.Attested {
		t.Fatalf("attested: dialer=%v server=%v, want both true", dAtt.Attested, sAtt.Attested)
	}
	// Each side must have verified the OTHER's role and endpoint ID.
	if dAtt.Claim.Role != RoleServe || dAtt.Claim.LocalEndpoint != serverID.String() {
		t.Fatalf("dialer saw peer role=%q local=%q, want serve/%s", dAtt.Claim.Role, dAtt.Claim.LocalEndpoint, serverID)
	}
	if sAtt.Claim.Role != RoleDial || sAtt.Claim.LocalEndpoint != dialerID.String() {
		t.Fatalf("server saw peer role=%q local=%q, want dial/%s", sAtt.Claim.Role, sAtt.Claim.LocalEndpoint, dialerID)
	}
}

func TestHandshakeVerifyOnlyPeerRejectedByDefault(t *testing.T) {
	// A verify-only peer sends no attestation; a mutual side without
	// AllowUnattested must reject it.
	dialerID, serverID := idOf(t), idOf(t)
	dialerCfg := HandshakeConfig{SelfID: dialerID, Mode: ModeMutual, Signer: newFakeSigner(t)}
	serverCfg := HandshakeConfig{SelfID: serverID, Mode: ModeVerify}

	_, _, dErr, _ := runPair(t, dialerCfg, serverCfg)
	if dErr == nil || !strings.Contains(dErr.Error(), "no attestation") {
		t.Fatalf("dialer err = %v, want a no-attestation rejection", dErr)
	}
}

func TestHandshakeVerifyOnlyPeerAllowed(t *testing.T) {
	// With AllowUnattested the mutual side accepts the verify-only peer as L0.
	dialerID, serverID := idOf(t), idOf(t)
	dialerCfg := HandshakeConfig{SelfID: dialerID, Mode: ModeMutual, Signer: newFakeSigner(t), Policy: Policy{AllowUnattested: true}}
	serverCfg := HandshakeConfig{SelfID: serverID, Mode: ModeVerify}

	dAtt, _, dErr, sErr := runPair(t, dialerCfg, serverCfg)
	if dErr != nil || sErr != nil {
		t.Fatalf("handshake errors: dialer=%v server=%v", dErr, sErr)
	}
	if dAtt == nil || dAtt.Attested {
		t.Fatalf("dialer att = %+v, want a non-attested L0 result", dAtt)
	}
}

func TestHandshakePolicyRejects(t *testing.T) {
	// A fake signer is not a real Enclave and reports no maximal flags, so
	// RequireMaximal must reject it.
	dialerID, serverID := idOf(t), idOf(t)
	dialerCfg := HandshakeConfig{SelfID: dialerID, Mode: ModeMutual, Signer: newFakeSigner(t), Policy: Policy{RequireMaximal: true}}
	serverCfg := HandshakeConfig{SelfID: serverID, Mode: ModeMutual, Signer: newFakeSigner(t)}

	_, _, dErr, _ := runPair(t, dialerCfg, serverCfg)
	if dErr == nil || !strings.Contains(dErr.Error(), "not maximal") {
		t.Fatalf("dialer err = %v, want a policy 'not maximal' rejection", dErr)
	}
}
