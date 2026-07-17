package enclaveiroh

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"slices"

	"github.com/tmc/go-iroh/key"
)

// ClaimContext is the domain-separation string signed into every Claim. A
// signature by the attestation key over these bytes can never be confused
// with any other use of that key. Any change to the SigningBytes layout must
// bump the version here, or two builds silently disagree on the signed bytes:
// /2 appended claim_version to the /1 layout.
const ClaimContext = "enclaveiroh-attest/2"

// Claim roles, from the QUIC side of the connection.
const (
	RoleDial  = "dial"
	RoleServe = "serve"
)

// A Claim is the signed unit of the attestation handshake (ATTEST.md): one
// side's self-report of its code identity, bound to the exact authenticated
// channel and session by both endpoint IDs and both Hello nonces. Byte-valued
// fields carry their encoded string forms (base64 nonces, hex hashes and
// keys); the signature covers those exact strings via [Claim.SigningBytes].
type Claim struct {
	Context        string `json:"context"`
	Role           string `json:"role"`
	LocalEndpoint  string `json:"local_endpoint"`
	RemoteEndpoint string `json:"remote_endpoint"`
	ALPN           string `json:"alpn"`
	NonceSelf      string `json:"nonce_self"` // base64 (std), 32 bytes
	NoncePeer      string `json:"nonce_peer"` // base64 (std), 32 bytes
	CDHash         string `json:"cdhash"`     // hex
	TeamID         string `json:"team_id"`
	CSFlags        uint32 `json:"cs_flags"`
	Bundled        bool   `json:"bundled"`
	EphemeralKey   bool   `json:"ephemeral_key"`
	AttestKey      string `json:"attest_key"` // X9.63 uncompressed P-256, hex
	Time           string `json:"time"`       // RFC3339

	// ClaimVersion is the operator-asserted monotonic build version, baked
	// into the binary at build time (see the enclave-iroh ldflags recipe) and
	// 0 when unset. The signature makes the assertion unforgeable for this
	// build; monotonicity across builds is the operator's promise, not the
	// protocol's. Verifiers gate on it with [Policy.MinClaimVersion].
	ClaimVersion uint64 `json:"claim_version"`
}

// SigningBytes returns the canonical length-prefixed binary serialization the
// signature covers: uvarint(len)‖bytes for each string field in wire order,
// cs_flags as a fixed 4-byte big-endian word, the bools as single bytes, and
// claim_version as a trailing uvarint. Length prefixes make field boundaries
// unambiguous (a crafted team_id cannot shift into cdhash), and the fixed
// layout keeps signature validity independent of any JSON marshaler.
func (c Claim) SigningBytes() []byte {
	b := make([]byte, 0, 512)
	for _, f := range []string{
		c.Context, c.Role, c.LocalEndpoint, c.RemoteEndpoint,
		c.ALPN, c.NonceSelf, c.NoncePeer, c.CDHash, c.TeamID,
	} {
		b = appendClaimField(b, f)
	}
	b = binary.BigEndian.AppendUint32(b, c.CSFlags)
	b = append(b, boolByte(c.Bundled), boolByte(c.EphemeralKey))
	for _, f := range []string{c.AttestKey, c.Time} {
		b = appendClaimField(b, f)
	}
	b = binary.AppendUvarint(b, c.ClaimVersion)
	return b
}

func appendClaimField(b []byte, f string) []byte {
	b = binary.AppendUvarint(b, uint64(len(f)))
	return append(b, f...)
}

func boolByte(v bool) byte {
	if v {
		return 1
	}
	return 0
}

// VerifyClaimSignature checks sig (ECDSA X9.62 DER over SHA-256) against the
// claim's SigningBytes using the attestation public key embedded in the claim.
// It uses only the standard library, so it runs on any platform. Pinning the
// embedded key is the caller's job, via [Policy].
func VerifyClaimSignature(c Claim, sig []byte) error {
	pubBytes, err := hex.DecodeString(c.AttestKey)
	if err != nil {
		return fmt.Errorf("decode attest_key: %w", err)
	}
	pub, err := parseP256PublicKey(pubBytes)
	if err != nil {
		return err
	}
	digest := sha256.Sum256(c.SigningBytes())
	if !ecdsa.VerifyASN1(pub, digest[:], sig) {
		return errors.New("claim signature does not verify against attest_key")
	}
	return nil
}

// VerifyClaim performs the structural, channel-binding, and freshness checks
// of ATTEST.md (steps 2–4) on a peer's claim, from the verifier's view of the
// connection: wantRole is the role the peer must claim (the complement of
// ours), self and peer are this connection's authenticated endpoint IDs, alpn
// is the connection's ALPN, selfNonce is the nonce we sent in our Hello, and
// peerNonce is the nonce the peer sent in theirs. Signature and policy checks
// are separate ([VerifyClaimSignature], [Policy.Check]).
func VerifyClaim(c Claim, wantRole string, self, peer key.EndpointID, alpn string, selfNonce, peerNonce []byte) error {
	if c.Context != ClaimContext {
		return fmt.Errorf("claim context %q, want %q", c.Context, ClaimContext)
	}
	if c.Role != wantRole {
		return fmt.Errorf("claim role %q, want %q (reflected or mislabeled claim)", c.Role, wantRole)
	}
	if c.LocalEndpoint != peer.String() {
		return fmt.Errorf("claim local_endpoint %s is not the connection peer %s", c.LocalEndpoint, peer)
	}
	if c.RemoteEndpoint != self.String() {
		return fmt.Errorf("claim remote_endpoint %s is not this endpoint %s", c.RemoteEndpoint, self)
	}
	if c.ALPN != alpn {
		return fmt.Errorf("claim alpn %q, want %q", c.ALPN, alpn)
	}
	if err := nonceEqual(c.NoncePeer, selfNonce); err != nil {
		return fmt.Errorf("claim nonce_peer: %w (replayed claim?)", err)
	}
	if err := nonceEqual(c.NonceSelf, peerNonce); err != nil {
		return fmt.Errorf("claim nonce_self: %w", err)
	}
	return nil
}

// nonceEqual compares a claim's base64 nonce field against the raw nonce in
// constant time.
func nonceEqual(field string, want []byte) error {
	got, err := base64.StdEncoding.DecodeString(field)
	if err != nil {
		return fmt.Errorf("decode: %w", err)
	}
	if len(got) != len(want) || subtle.ConstantTimeCompare(got, want) != 1 {
		return errors.New("does not match this session")
	}
	return nil
}

// A Policy is the verifier's acceptance criteria over a structurally valid,
// signature-verified peer claim — the T9 enforcement of THREAT-MODEL.md as
// code. The zero value accepts any attested peer; each field opts into a
// stricter check. The caller's choice of fields is the dial between L2
// (any attested peer) and L3 (pinned team, code, and key).
type Policy struct {
	// RequireMaximal requires the claimed cs_flags to satisfy [MaximalFlags]:
	// a valid Hardened Runtime signature, kill-on-tamper, enforcement,
	// library validation, not debuggable.
	RequireMaximal bool

	// RequireBundled requires the peer to have run inside a signed .app.
	RequireBundled bool

	// ForbidEphemeralKey rejects peers whose endpoint identity is ephemeral.
	ForbidEphemeralKey bool

	// MinClaimVersion, when nonzero, rejects a peer whose claim_version is
	// below it. The version is operator-asserted at build time, so this is a
	// rollback threshold — "reject anything below N" — rather than a pin set
	// that must enumerate every superseded build.
	MinClaimVersion uint64

	// AllowedTeamIDs, when non-empty, is the set of acceptable signing teams.
	AllowedTeamIDs []string

	// AllowedCDHashes, when non-empty, is the set of acceptable code
	// directory hashes, lowercase hex. This is also the rollback lever:
	// remove a superseded build's cdhash to stop accepting it.
	AllowedCDHashes []string

	// PinnedAttestKeys, when non-empty, is the set of acceptable attestation
	// public keys, X9.63 lowercase hex.
	PinnedAttestKeys []string

	// PinPeer, when set, is called with the peer's verified claim and
	// rejects it by returning an error. It is the hook for trust-on-first-use
	// stores ([KnownPeers.Pin] matches it): the claim carries both the
	// attestation key and the endpoint identity a store pins it under. TOFU
	// defends against a pinned key changing, not against impersonation on
	// first contact.
	PinPeer func(c Claim) error

	// AllowUnattested accepts a peer that sends no attestation (mode
	// "verify"), downgrading that connection to an explicit L0 result. The
	// handshake layer consults it; Check never sees an absent claim.
	AllowUnattested bool
}

// Check evaluates the policy against a peer claim that has already passed
// [VerifyClaimSignature] and [VerifyClaim].
func (p Policy) Check(c Claim) error {
	if p.RequireMaximal && !MaximalFlags(c.CSFlags) {
		return fmt.Errorf("policy: peer cs_flags 0x%08x are not maximal", c.CSFlags)
	}
	if p.RequireBundled && !c.Bundled {
		return errors.New("policy: peer did not run bundled")
	}
	if p.ForbidEphemeralKey && c.EphemeralKey {
		return errors.New("policy: peer endpoint key is ephemeral")
	}
	if p.MinClaimVersion > 0 && c.ClaimVersion < p.MinClaimVersion {
		return fmt.Errorf("policy: peer claim_version %d is below minimum %d", c.ClaimVersion, p.MinClaimVersion)
	}
	if len(p.AllowedTeamIDs) > 0 && !slices.Contains(p.AllowedTeamIDs, c.TeamID) {
		return fmt.Errorf("policy: peer team_id %q is not allowed", c.TeamID)
	}
	if len(p.AllowedCDHashes) > 0 && !slices.Contains(p.AllowedCDHashes, c.CDHash) {
		return fmt.Errorf("policy: peer cdhash %s is not allowed", c.CDHash)
	}
	if len(p.PinnedAttestKeys) > 0 && !slices.Contains(p.PinnedAttestKeys, c.AttestKey) {
		return errors.New("policy: peer attest_key is not pinned")
	}
	if p.PinPeer != nil {
		if err := p.PinPeer(c); err != nil {
			return fmt.Errorf("policy: pin peer: %w", err)
		}
	}
	return nil
}

// parseP256PublicKey parses an ANSI X9.63 uncompressed P-256 point
// (0x04 || X || Y). The crypto/ecdh round trip validates that the point is on
// the curve before the coordinates are trusted.
func parseP256PublicKey(b []byte) (*ecdsa.PublicKey, error) {
	if _, err := ecdh.P256().NewPublicKey(b); err != nil {
		return nil, fmt.Errorf("invalid P-256 public key: %w", err)
	}
	return &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     new(big.Int).SetBytes(b[1:33]),
		Y:     new(big.Int).SetBytes(b[33:65]),
	}, nil
}
