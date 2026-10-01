package x402iroh

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
	"time"

	"github.com/tmc/go-iroh/key"
	"github.com/tmc/x402"
)

// clockSkew backdates ValidAfter so a payment is valid on verifiers whose
// clocks run slightly behind the payer's.
const clockSkew = 30 * time.Second

// Wallet pays x402 challenges on the iroh:ed25519 network with an iroh
// endpoint key. It implements [x402.Payer]. The wallet's paying identity
// is Key's endpoint ID.
type Wallet struct {
	// Key signs payment authorizations.
	Key key.SecretKey

	// MaxAmount, when non-zero, caps the atomic units the wallet pays
	// for a single request.
	MaxAmount uint64
}

// Pay signs a payment for the first requirement in required.Accepts with
// scheme "exact" on network "iroh:ed25519" whose amount parses and is
// within MaxAmount.
func (w *Wallet) Pay(ctx context.Context, required *x402.PaymentRequired) (*x402.PaymentPayload, error) {
	for _, req := range required.Accepts {
		if req.Scheme != Scheme || req.Network != Network {
			continue
		}
		value, err := strconv.ParseUint(req.Amount, 10, 64)
		if err != nil {
			continue
		}
		if w.MaxAmount > 0 && value > w.MaxAmount {
			continue
		}
		return w.pay(req, required.Resource)
	}
	return nil, fmt.Errorf("x402iroh: no payable requirement (want scheme %q on network %q)", Scheme, Network)
}

func (w *Wallet) pay(req x402.PaymentRequirements, resource *x402.ResourceInfo) (*x402.PaymentPayload, error) {
	var nonce [32]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, fmt.Errorf("x402iroh: nonce: %w", err)
	}
	timeout := req.MaxTimeoutSeconds
	if timeout <= 0 {
		timeout = 60
	}
	now := time.Now()
	auth := Authorization{
		From:        w.Key.Public().EndpointID().String(),
		To:          req.PayTo,
		Value:       req.Amount,
		ValidAfter:  strconv.FormatInt(now.Add(-clockSkew).Unix(), 10),
		ValidBefore: strconv.FormatInt(now.Add(time.Duration(timeout)*time.Second).Unix(), 10),
		Nonce:       "0x" + hex.EncodeToString(nonce[:]),
	}
	payload, err := json.Marshal(ExactPayload{
		Signature:     SignAuthorization(w.Key, req.Network, auth),
		Authorization: auth,
	})
	if err != nil {
		return nil, fmt.Errorf("x402iroh: encode payload: %w", err)
	}
	return &x402.PaymentPayload{
		X402Version: x402.Version,
		Resource:    resource,
		Accepted:    req,
		Payload:     payload,
	}, nil
}
