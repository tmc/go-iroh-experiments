package x402iroh

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/tmc/go-iroh/key"
)

const (
	// Scheme is the x402 payment scheme implemented by this package.
	Scheme = "exact"

	// Network identifies iroh-native ed25519 payments. It follows the
	// CAIP-2 shape the x402 specification encourages for non-blockchain
	// networks.
	Network = "iroh:ed25519"
)

// Authorization is a payment authorization on the iroh:ed25519 network.
// It mirrors the EVM exact scheme's EIP-3009 field set with iroh endpoint
// identities: From and To are endpoint IDs in their canonical string form,
// Value is the amount in atomic units, ValidAfter and ValidBefore are Unix
// seconds as decimal strings, and Nonce is 32 random bytes in 0x-hex.
type Authorization struct {
	From        string `json:"from"`
	To          string `json:"to"`
	Value       string `json:"value"`
	ValidAfter  string `json:"validAfter"`
	ValidBefore string `json:"validBefore"`
	Nonce       string `json:"nonce"`
}

// ExactPayload is the scheme-specific payload carried in
// [x402.PaymentPayload].Payload: an authorization and its 0x-hex ed25519
// signature by the From endpoint's key.
type ExactPayload struct {
	Signature     string        `json:"signature"`
	Authorization Authorization `json:"authorization"`
}

const signingDomain = "x402/iroh/exact/1"

// signingMessage is the canonical byte encoding of an authorization: the
// domain, network, and each field, all length-prefixed, so no field value
// can shift another field's boundary.
func signingMessage(network string, a Authorization) []byte {
	var b []byte
	for _, f := range []string{signingDomain, network, a.From, a.To, a.Value, a.ValidAfter, a.ValidBefore, a.Nonce} {
		b = binary.AppendUvarint(b, uint64(len(f)))
		b = append(b, f...)
	}
	return b
}

// SignAuthorization signs a payment authorization with an endpoint secret
// key and returns the 0x-hex signature.
func SignAuthorization(sk key.SecretKey, network string, a Authorization) string {
	sig := sk.Sign(signingMessage(network, a))
	b := sig.Bytes()
	return "0x" + hex.EncodeToString(b[:])
}

// VerifyAuthorization checks an exact-scheme payload's signature against
// its From endpoint key and returns the payer's endpoint ID.
func VerifyAuthorization(network string, p ExactPayload) (key.EndpointID, error) {
	from, err := key.ParseEndpointID(p.Authorization.From)
	if err != nil {
		return key.EndpointID{}, fmt.Errorf("parse from: %w", err)
	}
	raw, err := hex.DecodeString(strings.TrimPrefix(p.Signature, "0x"))
	if err != nil {
		return key.EndpointID{}, fmt.Errorf("parse signature: %w", err)
	}
	sig, err := key.SignatureFromSlice(raw)
	if err != nil {
		return key.EndpointID{}, fmt.Errorf("parse signature: %w", err)
	}
	if err := from.PublicKey().Verify(signingMessage(network, p.Authorization), sig); err != nil {
		return key.EndpointID{}, fmt.Errorf("verify signature: %w", err)
	}
	return from, nil
}
