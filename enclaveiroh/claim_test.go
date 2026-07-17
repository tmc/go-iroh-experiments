package enclaveiroh

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/tmc/go-iroh/key"
)

// fakeSigner implements Signer with an in-memory P-256 key so the protocol
// core can be tested on any platform, without a Secure Enclave. It matches
// the Enclave signer's wire behavior: X9.63 public key, ASN.1 DER ECDSA over
// SHA-256 of the raw message.
type fakeSigner struct {
	priv *ecdsa.PrivateKey
}

func newFakeSigner(t *testing.T) *fakeSigner {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate fake signer key: %v", err)
	}
	return &fakeSigner{priv: priv}
}

func (s *fakeSigner) PublicKey() ([]byte, error) {
	pub, err := s.priv.PublicKey.ECDH()
	if err != nil {
		return nil, err
	}
	return pub.Bytes(), nil
}

func (s *fakeSigner) Sign(msg []byte) ([]byte, error) {
	digest := sha256.Sum256(msg)
	return ecdsa.SignASN1(rand.Reader, s.priv, digest[:])
}

func (s *fakeSigner) Verify(msg, signature []byte) (bool, error) {
	digest := sha256.Sum256(msg)
	return ecdsa.VerifyASN1(&s.priv.PublicKey, digest[:], signature), nil
}

func (s *fakeSigner) Release() {}

// testEndpointID returns a deterministic endpoint ID for tests.
func testEndpointID(t *testing.T, seed byte) key.EndpointID {
	t.Helper()
	var b [key.SeedSize]byte
	b[0] = seed
	b[31] = ^seed
	return key.NewSecretKey(b).Public().EndpointID()
}

// testClaim builds a valid signed claim between two test endpoints along with
// the verifier-side parameters that accept it.
func testClaim(t *testing.T, signer *fakeSigner) (c Claim, sig []byte, self, peer key.EndpointID, selfNonce, peerNonce []byte) {
	t.Helper()
	self = testEndpointID(t, 1)  // the verifier
	peer = testEndpointID(t, 2)  // the signer
	selfNonce = make([]byte, 32) // nonce the verifier sent
	peerNonce = make([]byte, 32) // nonce the signer sent
	for i := range selfNonce {
		selfNonce[i] = byte(i)
		peerNonce[i] = byte(0xff - i)
	}
	pub, err := signer.PublicKey()
	if err != nil {
		t.Fatalf("PublicKey() = %v", err)
	}
	c = Claim{
		Context:        ClaimContext,
		Role:           RoleServe, // the signer is the acceptor
		LocalEndpoint:  peer.String(),
		RemoteEndpoint: self.String(),
		ALPN:           "enclaveiroh/test/1",
		NonceSelf:      base64.StdEncoding.EncodeToString(peerNonce),
		NoncePeer:      base64.StdEncoding.EncodeToString(selfNonce),
		CDHash:         strings.Repeat("ab", 20),
		TeamID:         "TEAMID9999",
		CSFlags:        CSValid | CSRuntime | CSHard | CSKill | CSEnforcement | CSRequireLV,
		Bundled:        true,
		EphemeralKey:   false,
		AttestKey:      hex.EncodeToString(pub),
		Time:           time.Now().UTC().Format(time.RFC3339Nano),
	}
	sig, err = signer.Sign(c.SigningBytes())
	if err != nil {
		t.Fatalf("Sign() = %v", err)
	}
	return c, sig, self, peer, selfNonce, peerNonce
}

func TestClaimSignatureRoundTrip(t *testing.T) {
	signer := newFakeSigner(t)
	c, sig, _, _, _, _ := testClaim(t, signer)
	if err := VerifyClaimSignature(c, sig); err != nil {
		t.Fatalf("VerifyClaimSignature() = %v for a genuine signature", err)
	}
	sig[len(sig)-1] ^= 0xff
	if err := VerifyClaimSignature(c, sig); err == nil {
		t.Fatal("VerifyClaimSignature() = nil for a corrupted signature")
	}
}

// TestClaimSignatureCoversEveryField mutates each field of a signed claim and
// checks the signature stops verifying: nothing in the claim is outside the
// signed bytes.
func TestClaimSignatureCoversEveryField(t *testing.T) {
	signer := newFakeSigner(t)
	c, sig, _, _, _, _ := testClaim(t, signer)

	mutations := map[string]func(*Claim){
		"context":         func(c *Claim) { c.Context = "enclaveiroh-attest/1" },
		"role":            func(c *Claim) { c.Role = RoleDial },
		"local_endpoint":  func(c *Claim) { c.LocalEndpoint = c.RemoteEndpoint },
		"remote_endpoint": func(c *Claim) { c.RemoteEndpoint = c.LocalEndpoint },
		"alpn":            func(c *Claim) { c.ALPN = "other/1" },
		"nonce_self":      func(c *Claim) { c.NonceSelf = c.NoncePeer },
		"nonce_peer":      func(c *Claim) { c.NoncePeer = c.NonceSelf },
		"cdhash":          func(c *Claim) { c.CDHash = strings.Repeat("cd", 20) },
		"team_id":         func(c *Claim) { c.TeamID = "EVILTEAM00" },
		"cs_flags":        func(c *Claim) { c.CSFlags |= CSDebugged },
		"bundled":         func(c *Claim) { c.Bundled = !c.Bundled },
		"ephemeral_key":   func(c *Claim) { c.EphemeralKey = !c.EphemeralKey },
		"time":            func(c *Claim) { c.Time = "2000-01-01T00:00:00Z" },
		"claim_version":   func(c *Claim) { c.ClaimVersion++ },
	}
	for name, mutate := range mutations {
		mutated := c
		mutate(&mutated)
		if err := VerifyClaimSignature(mutated, sig); err == nil {
			t.Errorf("signature still verifies after mutating %s", name)
		}
	}
}

// TestSigningBytesFieldBoundaries checks the length prefixes make field
// boundaries unambiguous: moving a byte between adjacent fields changes the
// signed bytes.
func TestSigningBytesFieldBoundaries(t *testing.T) {
	a := Claim{TeamID: "AB", CDHash: "CDE"}
	b := Claim{TeamID: "ABC", CDHash: "DE"}
	if string(a.SigningBytes()) == string(b.SigningBytes()) {
		t.Fatal("shifting a byte across the team_id/cdhash boundary did not change SigningBytes")
	}
}

func TestVerifyClaim(t *testing.T) {
	signer := newFakeSigner(t)
	c, _, self, peer, selfNonce, peerNonce := testClaim(t, signer)

	if err := VerifyClaim(c, RoleServe, self, peer, c.ALPN, selfNonce, peerNonce); err != nil {
		t.Fatalf("VerifyClaim() = %v for a valid claim", err)
	}

	otherNonce := make([]byte, 32)
	tests := []struct {
		name string
		call func() error
	}{
		{"reflected role", func() error {
			return VerifyClaim(c, RoleDial, self, peer, c.ALPN, selfNonce, peerNonce)
		}},
		{"swapped endpoints", func() error {
			return VerifyClaim(c, RoleServe, peer, self, c.ALPN, selfNonce, peerNonce)
		}},
		{"wrong alpn", func() error {
			return VerifyClaim(c, RoleServe, self, peer, "other/1", selfNonce, peerNonce)
		}},
		{"replayed claim (stale verifier nonce)", func() error {
			return VerifyClaim(c, RoleServe, self, peer, c.ALPN, otherNonce, peerNonce)
		}},
		{"wrong peer hello nonce", func() error {
			return VerifyClaim(c, RoleServe, self, peer, c.ALPN, selfNonce, otherNonce)
		}},
		{"wrong context", func() error {
			bad := c
			bad.Context = "enclaveiroh-attest/0"
			return VerifyClaim(bad, RoleServe, self, peer, c.ALPN, selfNonce, peerNonce)
		}},
		{"superseded /1 context", func() error {
			bad := c
			bad.Context = "enclaveiroh-attest/1"
			return VerifyClaim(bad, RoleServe, self, peer, c.ALPN, selfNonce, peerNonce)
		}},
	}
	for _, tt := range tests {
		if err := tt.call(); err == nil {
			t.Errorf("VerifyClaim() = nil, want error for %s", tt.name)
		}
	}
}

func TestPolicyCheck(t *testing.T) {
	signer := newFakeSigner(t)
	c, _, _, _, _, _ := testClaim(t, signer)

	tests := []struct {
		name   string
		policy Policy
		claim  func() Claim
		wantOK bool
	}{
		{"zero policy accepts", Policy{}, func() Claim { return c }, true},
		{"maximal ok", Policy{RequireMaximal: true}, func() Claim { return c }, true},
		{"maximal rejects debugged", Policy{RequireMaximal: true}, func() Claim {
			bad := c
			bad.CSFlags |= CSDebugged
			return bad
		}, false},
		{"maximal rejects ad-hoc flags", Policy{RequireMaximal: true}, func() Claim {
			bad := c
			bad.CSFlags = CSValid | CSKill // what go run reports
			return bad
		}, false},
		{"bundled ok", Policy{RequireBundled: true}, func() Claim { return c }, true},
		{"bundled rejects unbundled", Policy{RequireBundled: true}, func() Claim {
			bad := c
			bad.Bundled = false
			return bad
		}, false},
		{"forbid ephemeral rejects", Policy{ForbidEphemeralKey: true}, func() Claim {
			bad := c
			bad.EphemeralKey = true
			return bad
		}, false},
		{"version threshold ok at minimum", Policy{MinClaimVersion: 2}, func() Claim {
			v := c
			v.ClaimVersion = 2
			return v
		}, true},
		{"version threshold rejects below (rollback)", Policy{MinClaimVersion: 2}, func() Claim {
			v := c
			v.ClaimVersion = 1
			return v
		}, false},
		{"zero threshold accepts unversioned", Policy{}, func() Claim { return c }, true},
		{"threshold rejects unversioned", Policy{MinClaimVersion: 1}, func() Claim { return c }, false},
		{"team pin ok", Policy{AllowedTeamIDs: []string{"TEAMID9999"}}, func() Claim { return c }, true},
		{"team pin rejects", Policy{AllowedTeamIDs: []string{"OTHERTEAM1"}}, func() Claim { return c }, false},
		{"cdhash pin ok", Policy{AllowedCDHashes: []string{strings.Repeat("ab", 20)}}, func() Claim { return c }, true},
		{"cdhash pin rejects (rollback)", Policy{AllowedCDHashes: []string{strings.Repeat("ee", 20)}}, func() Claim { return c }, false},
		{"attest key pin ok", Policy{PinnedAttestKeys: []string{c.AttestKey}}, func() Claim { return c }, true},
		{"attest key pin rejects", Policy{PinnedAttestKeys: []string{strings.Repeat("00", 65)}}, func() Claim { return c }, false},
		{"pin callback ok", Policy{PinPeer: func(Claim) error { return nil }}, func() Claim { return c }, true},
		{"pin callback rejects", Policy{PinPeer: func(Claim) error { return errors.New("key changed") }}, func() Claim { return c }, false},
	}
	for _, tt := range tests {
		err := tt.policy.Check(tt.claim())
		if ok := err == nil; ok != tt.wantOK {
			t.Errorf("%s: Check() = %v, want ok=%v", tt.name, err, tt.wantOK)
		}
	}
}

func TestMaximalFlags(t *testing.T) {
	maximal := uint32(CSValid | CSRuntime | CSHard | CSKill | CSEnforcement | CSRequireLV)
	if !MaximalFlags(maximal) {
		t.Fatal("MaximalFlags() = false for the full protection set")
	}
	if MaximalFlags(maximal | CSGetTaskAllow) {
		t.Fatal("MaximalFlags() = true with GET_TASK_ALLOW set")
	}
	if MaximalFlags(maximal | CSDebugged) {
		t.Fatal("MaximalFlags() = true with DEBUGGED set")
	}
	if MaximalFlags(CSValid | CSKill) {
		t.Fatal("MaximalFlags() = true for an ad-hoc go run flag set")
	}
}
