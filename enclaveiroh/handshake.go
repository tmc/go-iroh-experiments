package enclaveiroh

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/tmc/go-iroh/iroh"
	"github.com/tmc/go-iroh/key"
)

// Mode selects whether a side of the attestation handshake attests, verifies,
// or both. A non-darwin peer, which cannot produce an Enclave attestation, runs
// [ModeVerify] and needs no Signer.
type Mode int

const (
	// ModeMutual attests and requires the peer's attestation (the default).
	ModeMutual Mode = iota
	// ModeProve attests but does not require one from the peer.
	ModeProve
	// ModeVerify requires the peer's attestation but sends none.
	ModeVerify
)

func (m Mode) attests() bool  { return m == ModeMutual || m == ModeProve }
func (m Mode) verifies() bool { return m == ModeMutual || m == ModeVerify }

func (m Mode) String() string {
	switch m {
	case ModeMutual:
		return "mutual"
	case ModeProve:
		return "prove"
	case ModeVerify:
		return "verify"
	default:
		return fmt.Sprintf("Mode(%d)", int(m))
	}
}

func parseMode(s string) (Mode, error) {
	switch s {
	case "mutual":
		return ModeMutual, nil
	case "prove":
		return ModeProve, nil
	case "verify":
		return ModeVerify, nil
	default:
		return 0, fmt.Errorf("unknown handshake mode %q", s)
	}
}

const (
	// nonceSize is the length of each Hello nonce.
	nonceSize = 32
	// maxFrameSize caps a handshake frame, so a hostile length prefix cannot
	// force a large allocation.
	maxFrameSize = 1 << 16
	// handshakeTimeout bounds the whole exchange when the context has no
	// earlier deadline.
	handshakeTimeout = 15 * time.Second
)

// hello is the first message each side sends.
type hello struct {
	V     int    `json:"v"`
	Nonce string `json:"nonce"` // base64 std, nonceSize bytes
	Mode  string `json:"mode"`
}

// wireClaim carries a signed [Claim] on the attestation stream.
type wireClaim struct {
	Claim     Claim  `json:"claim"`
	Signature string `json:"signature"` // hex, ECDSA X9.62 DER
}

// result is the advisory outcome each side reports. It is not signed: the
// authoritative outcome is each side's own local verdict over the peer's claim.
type result struct {
	OK     bool   `json:"ok"`
	Reason string `json:"reason,omitempty"`
}

// HandshakeConfig configures one side of the attestation handshake.
type HandshakeConfig struct {
	// SelfID is this endpoint's ID (iroh.Endpoint.ID()). It is the
	// remote_endpoint the peer's claim must name.
	SelfID key.EndpointID

	// Mode selects attest/verify/both. The zero value is ModeMutual.
	Mode Mode

	// Signer signs this side's claim. Required when Mode attests.
	Signer Signer

	// Identity is this process's code identity (from LocalCodeIdentity),
	// reported in this side's claim.
	Identity CodeIdentity

	// Bundled and EphemeralKey report this run's provenance in the claim.
	Bundled      bool
	EphemeralKey bool

	// Policy is applied to the peer's claim when Mode verifies.
	Policy Policy
}

// PeerAttestation is the verified outcome of a handshake. Attested is false for
// an explicit L0 result — the peer sent no attestation and policy allowed it
// (AllowUnattested); Claim is then zero.
type PeerAttestation struct {
	Attested bool
	Claim    Claim
}

// Handshake runs the T6 channel-bound attestation handshake on conn's first
// bidirectional stream, before any application stream (see ATTEST.md). The
// dialer opens the stream and speaks first in each phase; the server accepts it.
//
// On success it returns the peer's verified attestation (or an L0 result). A
// failed verification is reported to the peer as an advisory Result before the
// error is returned, so a rejected peer learns why.
func Handshake(ctx context.Context, conn *iroh.Conn, cfg HandshakeConfig) (*PeerAttestation, error) {
	if cfg.Mode.attests() && cfg.Signer == nil {
		return nil, fmt.Errorf("handshake: mode %s attests but Signer is nil", cfg.Mode)
	}
	dialer := conn.Side() == iroh.SideClient
	stream, err := openHandshakeStream(ctx, conn, dialer)
	if err != nil {
		return nil, err
	}
	defer stream.Close()
	return runHandshake(ctx, stream, dialer, conn.RemoteID(), conn.ALPN(), cfg)
}

// runHandshake runs the handshake protocol over an already-open bidirectional
// stream. It is the transport-agnostic core of [Handshake]; tests drive it over
// a net.Pipe, and Handshake supplies an iroh stream. dialer selects who speaks
// first; peerID and alpn are the connection's authenticated peer ID and ALPN.
func runHandshake(ctx context.Context, stream net.Conn, dialer bool, peerID key.EndpointID, alpn string, cfg HandshakeConfig) (*PeerAttestation, error) {
	if cfg.Mode.attests() && cfg.Signer == nil {
		return nil, fmt.Errorf("handshake: mode %s attests but Signer is nil", cfg.Mode)
	}
	if dl, ok := ctx.Deadline(); ok {
		stream.SetDeadline(dl)
	} else {
		stream.SetDeadline(time.Now().Add(handshakeTimeout))
	}

	role := RoleServe
	if dialer {
		role = RoleDial
	}

	// Phase 1: exchange Hellos (nonces + modes). Transport errors abort.
	myNonce := make([]byte, nonceSize)
	if _, err := rand.Read(myNonce); err != nil {
		return nil, err
	}
	myHello := hello{V: 1, Nonce: base64.StdEncoding.EncodeToString(myNonce), Mode: cfg.Mode.String()}
	var peerHello hello
	if err := exchange(dialer,
		func() error { return writeFrame(stream, myHello) },
		func() error { return readFrame(stream, &peerHello) },
	); err != nil {
		return nil, fmt.Errorf("handshake hello: %w", err)
	}
	peerMode, err := parseMode(peerHello.Mode)
	if err != nil {
		return nil, fmt.Errorf("handshake: peer %w", err)
	}
	peerNonce, err := base64.StdEncoding.DecodeString(peerHello.Nonce)
	if err != nil || len(peerNonce) != nonceSize {
		return nil, fmt.Errorf("handshake: peer nonce is not %d base64 bytes", nonceSize)
	}

	// Phase 2: exchange attestations. What I send is set by my mode; what I
	// expect is set by mine AND the peer's. Transport errors abort; a failed
	// verification is captured so a courtesy Result still goes out.
	sendClaim := cfg.Mode.attests()
	expectClaim := cfg.Mode.verifies() && peerMode.attests()

	var peerAtt *PeerAttestation
	var verifyErr error

	send := func() error {
		if !sendClaim {
			return nil
		}
		claim, err := buildClaim(role, cfg, peerID, alpn, myNonce, peerNonce)
		if err != nil {
			return err
		}
		sig, err := cfg.Signer.Sign(claim.SigningBytes())
		if err != nil {
			return fmt.Errorf("sign claim: %w", err)
		}
		return writeFrame(stream, wireClaim{Claim: claim, Signature: hex.EncodeToString(sig)})
	}
	recv := func() error {
		if !cfg.Mode.verifies() {
			return nil // I don't care about the peer's claim (prove mode).
		}
		if !expectClaim {
			// Peer is verify-only and sends nothing. Enforce policy without
			// reading the stream (reading would deadlock).
			if !cfg.Policy.AllowUnattested {
				verifyErr = fmt.Errorf("peer sent no attestation (mode %s) and AllowUnattested is false", peerMode)
				return nil
			}
			peerAtt = &PeerAttestation{Attested: false}
			return nil
		}
		var wc wireClaim
		if err := readFrame(stream, &wc); err != nil {
			return err // transport error
		}
		verifyErr = verifyPeerClaim(wc, role, cfg, peerID, alpn, myNonce, peerNonce)
		if verifyErr == nil {
			peerAtt = &PeerAttestation{Attested: true, Claim: wc.Claim}
		}
		return nil
	}
	if err := exchange(dialer, send, recv); err != nil {
		return nil, fmt.Errorf("handshake attestation: %w", err)
	}

	// Phase 3: exchange advisory Results (not signed). Report my verdict on the
	// peer so a rejected peer learns why before the connection closes.
	myResult := result{OK: verifyErr == nil}
	if verifyErr != nil {
		myResult.Reason = verifyErr.Error()
	}
	var peerResult result
	_ = exchange(dialer,
		func() error { return writeFrame(stream, myResult) },
		func() error { return readFrame(stream, &peerResult) },
	)

	if verifyErr != nil {
		return nil, verifyErr
	}
	return peerAtt, nil
}

// verifyPeerClaim runs the signature, structural/channel-binding, and policy
// checks on a peer's claim.
func verifyPeerClaim(wc wireClaim, myRole string, cfg HandshakeConfig, peerID key.EndpointID, alpn string, myNonce, peerNonce []byte) error {
	sig, err := hex.DecodeString(wc.Signature)
	if err != nil {
		return fmt.Errorf("decode claim signature: %w", err)
	}
	if err := VerifyClaimSignature(wc.Claim, sig); err != nil {
		return err
	}
	wantRole := RoleDial
	if myRole == RoleDial {
		wantRole = RoleServe
	}
	if err := VerifyClaim(wc.Claim, wantRole, cfg.SelfID, peerID, alpn, myNonce, peerNonce); err != nil {
		return err
	}
	return cfg.Policy.Check(wc.Claim)
}

// buildClaim assembles this side's claim for the connection.
func buildClaim(role string, cfg HandshakeConfig, peerID key.EndpointID, alpn string, myNonce, peerNonce []byte) (Claim, error) {
	pub, err := cfg.Signer.PublicKey()
	if err != nil {
		return Claim{}, fmt.Errorf("export attest key: %w", err)
	}
	return Claim{
		Context:        ClaimContext,
		Role:           role,
		LocalEndpoint:  cfg.SelfID.String(),
		RemoteEndpoint: peerID.String(),
		ALPN:           alpn,
		NonceSelf:      base64.StdEncoding.EncodeToString(myNonce),
		NoncePeer:      base64.StdEncoding.EncodeToString(peerNonce),
		CDHash:         hex.EncodeToString(cfg.Identity.CDHash),
		TeamID:         cfg.Identity.TeamID,
		CSFlags:        cfg.Identity.Flags,
		Bundled:        cfg.Bundled,
		EphemeralKey:   cfg.EphemeralKey,
		AttestKey:      hex.EncodeToString(pub),
		Time:           time.Now().UTC().Format(time.RFC3339),
	}, nil
}

// openHandshakeStream opens (dialer) or accepts (server) the first
// bidirectional stream of the connection, which carries the handshake.
func openHandshakeStream(ctx context.Context, conn *iroh.Conn, dialer bool) (net.Conn, error) {
	if dialer {
		s, err := conn.OpenStreamConn(ctx)
		if err != nil {
			return nil, fmt.Errorf("open handshake stream: %w", err)
		}
		return s, nil
	}
	s, err := conn.AcceptStreamConn(ctx)
	if err != nil {
		return nil, fmt.Errorf("accept handshake stream: %w", err)
	}
	return s, nil
}

// exchange runs send then recv in dialer-first order (server does recv then
// send), so a single bidirectional stream never deadlocks: each side's write is
// matched by the other's read. A nil callback is skipped.
func exchange(dialer bool, send, recv func() error) error {
	first, second := send, recv
	if !dialer {
		first, second = recv, send
	}
	if first != nil {
		if err := first(); err != nil {
			return err
		}
	}
	if second != nil {
		if err := second(); err != nil {
			return err
		}
	}
	return nil
}

// writeFrame writes v as a length-prefixed JSON frame (4-byte big-endian length
// then the JSON body).
func writeFrame(w io.Writer, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	if len(b) > maxFrameSize {
		return fmt.Errorf("frame too large: %d bytes", len(b))
	}
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(b)))
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	_, err = w.Write(b)
	return err
}

// readFrame reads a length-prefixed JSON frame written by writeFrame into v.
func readFrame(r io.Reader, v any) error {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return err
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if n > maxFrameSize {
		return fmt.Errorf("frame too large: %d bytes", n)
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return err
	}
	return json.Unmarshal(buf, v)
}
