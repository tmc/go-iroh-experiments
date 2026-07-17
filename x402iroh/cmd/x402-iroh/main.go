// X402-iroh runs x402-paid HTTP over real iroh endpoints.
//
// Usage:
//
//	x402-iroh demo
//	x402-iroh facilitator [-faucet <n>] [-bind <addr>]
//	x402-iroh serve -facilitator <ticket> [-price <n>] [-bind <addr>]
//	x402-iroh get -server <ticket> [-path <p>] [-max <n>] [-bind <addr>]
//
// The demo subcommand runs the whole flow in one process on loopback: a
// ledger facilitator, a paywalled resource server that verifies and
// settles through it, and a client that pays with its endpoint key.
//
// The other subcommands run the roles as separate processes. The
// facilitator serves an in-memory credit ledger (every new account starts
// with the faucet balance) and prints its ticket. Serve runs a paid hello
// server against a facilitator and prints its ticket. Get fetches a path
// from a server, paying the challenge automatically, and prints the body
// and the settlement.
//
// Endpoints bind to IPv6 loopback by default; pass -bind to serve a
// reachable address. Endpoint keys are ephemeral, so ledger accounts do
// not survive restarts.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/tmc/go-iroh-experiments/x402iroh"
	"github.com/tmc/go-iroh/endpointticket"
	"github.com/tmc/go-iroh/iroh"
	"github.com/tmc/go-iroh/netaddr"
	"github.com/tmc/x402"
)

func usage() {
	fmt.Fprintf(os.Stderr, `usage:
	x402-iroh demo
	x402-iroh facilitator [-faucet <n>] [-bind <addr>]
	x402-iroh serve -facilitator <ticket> [-price <n>] [-bind <addr>]
	x402-iroh get -server <ticket> [-path <p>] [-max <n>] [-bind <addr>]
`)
	os.Exit(2)
}

func main() {
	log.SetFlags(0)
	log.SetPrefix("x402-iroh: ")
	if len(os.Args) < 2 {
		usage()
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	var err error
	switch os.Args[1] {
	case "demo":
		err = runDemo(ctx, os.Args[2:])
	case "facilitator":
		err = runFacilitator(ctx, os.Args[2:])
	case "serve":
		err = runServe(ctx, os.Args[2:])
	case "get":
		err = runGet(ctx, os.Args[2:])
	default:
		usage()
	}
	if err != nil {
		log.Fatal(err)
	}
}

// bind binds an endpoint on addr (loopback default) with the x402iroh ALPN.
func bind(ctx context.Context, addr string) (*iroh.Endpoint, error) {
	bindAddr := netip.AddrPortFrom(netip.IPv6Loopback(), 0)
	if addr != "" {
		parsed, err := netip.ParseAddrPort(addr)
		if err != nil {
			return nil, fmt.Errorf("parse -bind: %w", err)
		}
		bindAddr = parsed
	}
	return iroh.Bind(ctx, iroh.WithALPNs(x402iroh.ALPN), iroh.WithBindAddr(bindAddr))
}

func ticketFor(ep *iroh.Endpoint) string {
	return endpointticket.Encode(netaddr.NewEndpointAddr(ep.ID()).WithIP(ep.LocalAddr()))
}

func connect(ctx context.Context, ep *iroh.Endpoint, ticket string) (*iroh.Conn, error) {
	addr, err := endpointticket.Decode(ticket)
	if err != nil {
		return nil, fmt.Errorf("parse ticket: %w", err)
	}
	return ep.Connect(ctx, addr, x402iroh.ALPN)
}

func runFacilitator(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("facilitator", flag.ExitOnError)
	faucet := fs.Uint64("faucet", 100, "starting balance for new accounts")
	bindAddr := fs.String("bind", "", "bind address (default IPv6 loopback)")
	fs.Parse(args)

	ep, err := bind(ctx, *bindAddr)
	if err != nil {
		return err
	}
	defer ep.Shutdown(context.Background())
	ledger := x402iroh.NewLedger()
	ledger.Faucet = *faucet
	fmt.Printf("facilitator: %s\nticket: %s\n", ep.ID(), ticketFor(ep))
	go x402iroh.Serve(ep, x402.FacilitatorHandler(ledger))
	<-ctx.Done()
	return nil
}

func runServe(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	facilitatorTicket := fs.String("facilitator", "", "facilitator ticket (required)")
	price := fs.Uint64("price", 5, "price per request in credits")
	bindAddr := fs.String("bind", "", "bind address (default IPv6 loopback)")
	fs.Parse(args)
	if *facilitatorTicket == "" {
		fs.Usage()
		os.Exit(2)
	}

	ep, err := bind(ctx, *bindAddr)
	if err != nil {
		return err
	}
	defer ep.Shutdown(context.Background())
	facConn, err := connect(ctx, ep, *facilitatorTicket)
	if err != nil {
		return err
	}
	defer facConn.Close()

	paywall := &x402.Paywall{
		Accepts: x402.StaticAccepts(x402.PaymentRequirements{
			Scheme:            x402iroh.Scheme,
			Network:           x402iroh.Network,
			Amount:            fmt.Sprint(*price),
			Asset:             "credit",
			PayTo:             ep.ID().String(),
			MaxTimeoutSeconds: 60,
		}),
		Facilitator: &x402.FacilitatorClient{
			BaseURL: "http://" + facConn.RemoteID().String(),
			Client:  &http.Client{Transport: x402iroh.NewTransport(facConn)},
		},
	}
	fmt.Printf("server: %s\nticket: %s\n", ep.ID(), ticketFor(ep))
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "hello from %s: %s costs %d credits (served %s)\n",
			ep.ID().Short(), r.URL.Path, *price, time.Now().Format(time.RFC3339))
	})
	go x402iroh.Serve(ep, paywall.Handler(handler))
	<-ctx.Done()
	return nil
}

func runGet(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("get", flag.ExitOnError)
	serverTicket := fs.String("server", "", "server ticket (required)")
	path := fs.String("path", "/", "path to fetch")
	maxAmount := fs.Uint64("max", 0, "refuse to pay more than this (0 = no cap)")
	bindAddr := fs.String("bind", "", "bind address (default IPv6 loopback)")
	fs.Parse(args)
	if *serverTicket == "" {
		fs.Usage()
		os.Exit(2)
	}

	ep, err := bind(ctx, *bindAddr)
	if err != nil {
		return err
	}
	defer ep.Shutdown(context.Background())
	conn, err := connect(ctx, ep, *serverTicket)
	if err != nil {
		return err
	}
	defer conn.Close()

	client := x402iroh.NewClient(conn, &x402iroh.Wallet{Key: ep.SecretKey(), MaxAmount: *maxAmount})
	resp, err := client.Get("http://" + conn.RemoteID().String() + *path)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	fmt.Printf("status: %s\n%s", resp.Status, body)
	if header := resp.Header.Get(x402.HeaderPaymentResponse); header != "" {
		var settle x402.SettleResponse
		if err := x402.DecodeHeader(header, &settle); err == nil {
			fmt.Printf("settled: %v amount=%s tx=%s\n", settle.Success, settle.Amount, settle.Transaction)
		}
	}
	return nil
}

func runDemo(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("demo", flag.ExitOnError)
	fs.Parse(args)

	// Facilitator peer with a demo faucet.
	facilitator, err := bind(ctx, "")
	if err != nil {
		return err
	}
	defer facilitator.Shutdown(context.Background())
	ledger := x402iroh.NewLedger()
	ledger.Faucet = 12
	go x402iroh.Serve(facilitator, x402.FacilitatorHandler(ledger))
	fmt.Printf("facilitator %s (faucet 12 credits)\n", facilitator.ID().Short())

	// Paywalled resource server peer.
	server, err := bind(ctx, "")
	if err != nil {
		return err
	}
	defer server.Shutdown(context.Background())
	facConn, err := server.Connect(ctx, netaddr.NewEndpointAddr(facilitator.ID()).WithIP(facilitator.LocalAddr()), x402iroh.ALPN)
	if err != nil {
		return err
	}
	defer facConn.Close()
	paywall := &x402.Paywall{
		Accepts: x402.StaticAccepts(x402.PaymentRequirements{
			Scheme:            x402iroh.Scheme,
			Network:           x402iroh.Network,
			Amount:            "5",
			Asset:             "credit",
			PayTo:             server.ID().String(),
			MaxTimeoutSeconds: 60,
		}),
		Facilitator: &x402.FacilitatorClient{
			BaseURL: "http://" + facilitator.ID().String(),
			Client:  &http.Client{Transport: x402iroh.NewTransport(facConn)},
		},
	}
	go x402iroh.Serve(server, paywall.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "premium content from %s\n", server.ID().Short())
	})))
	fmt.Printf("server      %s (5 credits per request)\n", server.ID().Short())

	// Paying client peer.
	client, err := bind(ctx, "")
	if err != nil {
		return err
	}
	defer client.Shutdown(context.Background())
	conn, err := client.Connect(ctx, netaddr.NewEndpointAddr(server.ID()).WithIP(server.LocalAddr()), x402iroh.ALPN)
	if err != nil {
		return err
	}
	defer conn.Close()
	hc := x402iroh.NewClient(conn, &x402iroh.Wallet{Key: client.SecretKey()})
	fmt.Printf("client      %s\n\n", client.ID().Short())

	for i := 1; i <= 3; i++ {
		resp, err := hc.Get("http://" + server.ID().String() + "/premium")
		if err != nil {
			return err
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		fmt.Printf("request %d: %s", i, resp.Status)
		if header := resp.Header.Get(x402.HeaderPaymentResponse); header != "" {
			var settle x402.SettleResponse
			if x402.DecodeHeader(header, &settle) == nil && settle.Success {
				fmt.Printf(" (paid %s credits, tx %s...)", settle.Amount, settle.Transaction[:10])
			}
		}
		fmt.Printf("\n  %s", body)
		if len(body) > 0 && body[len(body)-1] != '\n' {
			fmt.Println()
		}
		fmt.Printf("  client balance: %d credits\n", ledger.Balance(client.ID()))
	}
	fmt.Println("\nthe third request fails: the faucet granted 12 credits and two requests cost 10,")
	fmt.Println("so the client cannot cover another 5. x402 refuses cleanly with a 402 challenge.")
	return nil
}
