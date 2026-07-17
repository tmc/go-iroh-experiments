package x402iroh_test

import (
	"context"
	"io"
	"net/http"
	"net/netip"
	"testing"
	"time"

	"github.com/tmc/go-iroh-experiments/x402iroh"
	"github.com/tmc/go-iroh/iroh"
	"github.com/tmc/go-iroh/netaddr"
	"github.com/tmc/x402"
)

// bindLoopback binds an endpoint on the IPv6 loopback for in-process tests.
func bindLoopback(t *testing.T, ctx context.Context, alpns ...string) *iroh.Endpoint {
	t.Helper()
	opts := []iroh.Option{iroh.WithBindAddr(netip.AddrPortFrom(netip.IPv6Loopback(), 0))}
	if len(alpns) > 0 {
		opts = append(opts, iroh.WithALPNs(alpns...))
	}
	ep, err := iroh.Bind(ctx, opts...)
	if err != nil {
		t.Fatalf("bind: %v", err)
	}
	t.Cleanup(func() { ep.Shutdown(context.Background()) })
	return ep
}

func dial(t *testing.T, ctx context.Context, from, to *iroh.Endpoint) *iroh.Conn {
	t.Helper()
	conn, err := from.Connect(ctx, netaddr.NewEndpointAddr(to.ID()).WithIP(to.LocalAddr()), x402iroh.ALPN)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(func() { conn.Close() })
	return conn
}

// TestPaidRequestOverIroh runs the full x402 flow between three iroh
// endpoints: a ledger facilitator, a paywalled resource server that
// verifies and settles through the facilitator over iroh, and a client
// that pays with its endpoint key.
func TestPaidRequestOverIroh(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Facilitator peer: an in-memory ledger served over iroh.
	facilitator := bindLoopback(t, ctx, x402iroh.ALPN)
	ledger := x402iroh.NewLedger()
	go x402iroh.Serve(facilitator, x402.FacilitatorHandler(ledger))

	// Resource server peer: a paywalled handler; verification and
	// settlement go to the facilitator peer over iroh.
	server := bindLoopback(t, ctx, x402iroh.ALPN)
	price := x402.PaymentRequirements{
		Scheme:            x402iroh.Scheme,
		Network:           x402iroh.Network,
		Amount:            "5",
		Asset:             "credit",
		PayTo:             server.ID().String(),
		MaxTimeoutSeconds: 60,
	}
	facConn := dial(t, ctx, server, facilitator)
	paywall := &x402.Paywall{
		Accepts: x402.StaticAccepts(price),
		Facilitator: &x402.FacilitatorClient{
			BaseURL: "http://" + facilitator.ID().String(),
			Client:  &http.Client{Transport: x402iroh.NewTransport(facConn)},
		},
	}
	go x402iroh.Serve(server, paywall.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "paid content over iroh")
	})))

	// Client peer: pays with its endpoint key from a funded account.
	client := bindLoopback(t, ctx)
	ledger.Credit(client.ID(), 12)
	serverConn := dial(t, ctx, client, server)
	hc := x402iroh.NewClient(serverConn, &x402iroh.Wallet{Key: client.SecretKey()})
	url := "http://" + server.ID().String() + "/hello"

	get := func() *http.Response {
		t.Helper()
		resp, err := hc.Get(url)
		if err != nil {
			t.Fatalf("get: %v", err)
		}
		t.Cleanup(func() { resp.Body.Close() })
		return resp
	}

	// First request: pays 5, succeeds.
	resp := get()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, body %q", resp.StatusCode, body)
	}
	if string(body) != "paid content over iroh" {
		t.Errorf("body = %q", body)
	}
	var settle x402.SettleResponse
	if err := x402.DecodeHeader(resp.Header.Get(x402.HeaderPaymentResponse), &settle); err != nil {
		t.Fatalf("decode settle header: %v", err)
	}
	if !settle.Success || settle.Payer != client.ID().String() || settle.Amount != "5" {
		t.Errorf("settle = %+v", settle)
	}
	if got := ledger.Balance(client.ID()); got != 7 {
		t.Errorf("client balance = %d, want 7", got)
	}
	if got := ledger.Balance(server.ID()); got != 5 {
		t.Errorf("server balance = %d, want 5", got)
	}

	// Second request: pays again with a fresh nonce.
	resp = get()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("second request status = %d", resp.StatusCode)
	}
	io.Copy(io.Discard, resp.Body)
	if got := ledger.Balance(client.ID()); got != 2 {
		t.Errorf("client balance after second payment = %d, want 2", got)
	}

	// Third request: 2 credits left, price is 5: verification fails and
	// the client sees the 402 challenge.
	resp = get()
	if resp.StatusCode != http.StatusPaymentRequired {
		t.Fatalf("broke request status = %d, want 402", resp.StatusCode)
	}
	var challenge x402.PaymentRequired
	if err := x402.DecodeHeader(resp.Header.Get(x402.HeaderPaymentRequired), &challenge); err != nil {
		t.Fatalf("decode challenge: %v", err)
	}
	if challenge.Error != x402.ReasonInsufficientFunds {
		t.Errorf("challenge error = %q, want %q", challenge.Error, x402.ReasonInsufficientFunds)
	}
	if got := ledger.Balance(client.ID()); got != 2 {
		t.Errorf("failed payment moved funds: balance = %d, want 2", got)
	}
}

// TestUnpaidRequestChallenged checks a client with no payer receives the
// 402 challenge unchanged.
func TestUnpaidRequestChallenged(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	server := bindLoopback(t, ctx, x402iroh.ALPN)
	price := x402.PaymentRequirements{
		Scheme:  x402iroh.Scheme,
		Network: x402iroh.Network,
		Amount:  "5",
		Asset:   "credit",
		PayTo:   server.ID().String(),
	}
	paywall := &x402.Paywall{
		Accepts:     x402.StaticAccepts(price),
		Facilitator: x402iroh.NewLedger(),
	}
	go x402iroh.Serve(server, paywall.Handler(http.NotFoundHandler()))

	client := bindLoopback(t, ctx)
	conn := dial(t, ctx, client, server)
	hc := x402iroh.NewClient(conn, nil)
	resp, err := hc.Get("http://" + server.ID().String() + "/")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusPaymentRequired {
		t.Errorf("status = %d, want 402", resp.StatusCode)
	}
	var challenge x402.PaymentRequired
	if err := x402.DecodeHeader(resp.Header.Get(x402.HeaderPaymentRequired), &challenge); err != nil {
		t.Fatalf("decode challenge: %v", err)
	}
	if len(challenge.Accepts) != 1 || challenge.Accepts[0].Network != x402iroh.Network {
		t.Errorf("challenge = %+v", challenge)
	}
}

// TestLedgerZeroValue checks a literal Ledger works without NewLedger.
func TestLedgerZeroValue(t *testing.T) {
	ctx := context.Background()
	ledger := &x402iroh.Ledger{Faucet: 10}
	ep, err := iroh.Bind(ctx, iroh.WithBindAddr(netip.AddrPortFrom(netip.IPv6Loopback(), 0)))
	if err != nil {
		t.Fatalf("bind: %v", err)
	}
	defer ep.Shutdown(ctx)
	if got := ledger.Balance(ep.ID()); got != 10 {
		t.Errorf("faucet balance = %d, want 10", got)
	}
	ledger.Credit(ep.ID(), 5)
	if got := ledger.Balance(ep.ID()); got != 15 {
		t.Errorf("credited balance = %d, want 15", got)
	}
}
