package x402iroh

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/tmc/go-iroh/key"
	"github.com/tmc/x402"
)

// defaultMaxValidity bounds an authorization's remaining lifetime, keeping
// the nonce replay set (and the exposure of a restarted ledger) bounded.
const defaultMaxValidity = 5 * time.Minute

// Ledger is an in-memory x402 facilitator for the iroh:ed25519 network:
// account balances keyed by endpoint ID, settled by moving credit between
// accounts. It implements [x402.Facilitator] and [x402.SupportedReporter]
// and is safe for concurrent use.
//
// Ledger is an experiment: balances and spent nonces live in memory only.
type Ledger struct {
	// Faucet, when non-zero, is the starting balance granted to every
	// account the first time it is seen.
	Faucet uint64

	// MaxValidity bounds how far in the future an authorization's
	// ValidBefore may lie. Zero means 5 minutes.
	MaxValidity time.Duration

	mu       sync.Mutex
	balances map[string]uint64
	spent    map[string]bool // nonces of settled payments
}

// NewLedger returns an empty ledger. The zero value is also usable.
func NewLedger() *Ledger {
	return &Ledger{}
}

// Credit adds amount to an account.
func (l *Ledger) Credit(id key.EndpointID, amount uint64) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.account(id.String())
	l.balances[id.String()] += amount
}

// Balance returns an account's balance, applying the faucet to accounts
// not seen before.
func (l *Ledger) Balance(id key.EndpointID) uint64 {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.account(id.String())
}

// account returns an account's balance, creating it with the faucet
// balance on first sight. The caller holds l.mu.
func (l *Ledger) account(id string) uint64 {
	if l.balances == nil {
		l.balances = make(map[string]uint64)
	}
	if _, ok := l.balances[id]; !ok {
		l.balances[id] = l.Faucet
	}
	return l.balances[id]
}

// Verify checks a payment without settling it.
func (l *Ledger) Verify(ctx context.Context, payload *x402.PaymentPayload, reqs x402.PaymentRequirements) (*x402.VerifyResponse, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	checked, invalid := l.check(payload, reqs)
	if invalid != nil {
		return invalid, nil
	}
	return &x402.VerifyResponse{IsValid: true, Payer: checked.from}, nil
}

// Settle executes a payment: it re-checks it, marks its nonce spent, and
// moves the amount from payer to payee.
func (l *Ledger) Settle(ctx context.Context, payload *x402.PaymentPayload, reqs x402.PaymentRequirements) (*x402.SettleResponse, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	checked, invalid := l.check(payload, reqs)
	if invalid != nil {
		return &x402.SettleResponse{
			Success:      false,
			ErrorReason:  invalid.InvalidReason,
			ErrorMessage: invalid.InvalidMessage,
			Payer:        invalid.Payer,
			Network:      reqs.Network,
		}, nil
	}
	if l.spent == nil {
		l.spent = make(map[string]bool)
	}
	l.spent[checked.auth.Nonce] = true
	l.balances[checked.from] -= checked.value
	l.account(checked.to)
	l.balances[checked.to] += checked.value
	sum := sha256.Sum256(signingMessage(reqs.Network, checked.auth))
	return &x402.SettleResponse{
		Success:     true,
		Payer:       checked.from,
		Transaction: "0x" + hex.EncodeToString(sum[:]),
		Network:     reqs.Network,
		Amount:      checked.auth.Value,
	}, nil
}

// Supported reports the single payment kind the ledger settles.
func (l *Ledger) Supported(ctx context.Context) (*x402.SupportedResponse, error) {
	return &x402.SupportedResponse{
		Kinds:      []x402.SupportedKind{{Version: x402.Version, Scheme: Scheme, Network: Network}},
		Extensions: []string{},
		Signers:    map[string][]string{},
	}, nil
}

// checkedPayment is a payment that passed all checks: canonical payer and
// payee account IDs and the parsed amount.
type checkedPayment struct {
	auth  Authorization
	from  string
	to    string
	value uint64
}

// invalid builds a verification failure.
func invalid(reason, message string) *x402.VerifyResponse {
	return &x402.VerifyResponse{IsValid: false, InvalidReason: reason, InvalidMessage: message}
}

// check validates a payment against the requirements, the clock, the nonce
// set, and account balances. The caller holds l.mu.
func (l *Ledger) check(payload *x402.PaymentPayload, reqs x402.PaymentRequirements) (checkedPayment, *x402.VerifyResponse) {
	var c checkedPayment
	if payload.Version != x402.Version {
		return c, invalid(x402.ReasonInvalidVersion, "")
	}
	if reqs.Scheme != Scheme {
		return c, invalid(x402.ReasonUnsupportedScheme, "scheme "+reqs.Scheme)
	}
	if reqs.Network != Network {
		return c, invalid(x402.ReasonInvalidNetwork, "network "+reqs.Network)
	}
	var exact ExactPayload
	if err := json.Unmarshal(payload.Payload, &exact); err != nil {
		return c, invalid(x402.ReasonInvalidPayload, "malformed exact payload")
	}
	auth := exact.Authorization

	payTo, err := key.ParseEndpointID(reqs.PayTo)
	if err != nil {
		return c, invalid(x402.ReasonInvalidRequirements, "payTo is not an endpoint id")
	}
	to, err := key.ParseEndpointID(auth.To)
	if err != nil || !to.Equal(payTo) {
		return c, invalid(x402.ReasonInvalidPayload, "recipient mismatch")
	}
	value, err := strconv.ParseUint(auth.Value, 10, 64)
	if err != nil {
		return c, invalid(x402.ReasonInvalidPayload, "bad value")
	}
	required, err := strconv.ParseUint(reqs.Amount, 10, 64)
	if err != nil || value != required {
		return c, invalid(x402.ReasonInvalidPayload, "value mismatch")
	}

	now := time.Now()
	validAfter, err1 := strconv.ParseInt(auth.ValidAfter, 10, 64)
	validBefore, err2 := strconv.ParseInt(auth.ValidBefore, 10, 64)
	if err1 != nil || err2 != nil {
		return c, invalid(x402.ReasonInvalidPayload, "bad validity window")
	}
	if now.Unix() < validAfter {
		return c, invalid(x402.ReasonInvalidPayload, "authorization not yet valid")
	}
	if now.Unix() > validBefore {
		return c, invalid(x402.ReasonInvalidPayload, "authorization expired")
	}
	maxValidity := l.MaxValidity
	if maxValidity == 0 {
		maxValidity = defaultMaxValidity
	}
	if time.Unix(validBefore, 0).After(now.Add(maxValidity)) {
		return c, invalid(x402.ReasonInvalidPayload, "validity window too long")
	}

	nonce := strings.TrimPrefix(auth.Nonce, "0x")
	if raw, err := hex.DecodeString(nonce); err != nil || len(raw) != 32 {
		return c, invalid(x402.ReasonInvalidPayload, "bad nonce")
	}
	if l.spent[auth.Nonce] {
		return c, invalid(x402.ReasonInvalidPayload, "nonce already spent")
	}

	from, err := VerifyAuthorization(reqs.Network, exact)
	if err != nil {
		return c, invalid(x402.ReasonInvalidPayload, err.Error())
	}
	c = checkedPayment{auth: auth, from: from.String(), to: to.String(), value: value}
	if l.account(c.from) < value {
		return c, &x402.VerifyResponse{
			IsValid:       false,
			InvalidReason: x402.ReasonInsufficientFunds,
			Payer:         c.from,
		}
	}
	return c, nil
}
