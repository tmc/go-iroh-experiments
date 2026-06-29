package main

import (
	"context"
	"flag"
	"fmt"
	"net/netip"
	"os"
	"os/signal"
	"time"

	"github.com/tmc/go-iroh-experiments/contentdiscovery"
	"github.com/tmc/go-iroh/iroh"
)

func main() {
	if err := run(context.Background(), os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
}

func run(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("content-tracker", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	listen := fs.String("listen", "[::1]:0", "UDP listen address")
	expiry := fs.Duration("expiry", 7*24*time.Hour, "announce expiry")
	if err := fs.Parse(args); err != nil {
		return err
	}
	ap, err := netip.ParseAddrPort(*listen)
	if err != nil {
		return fmt.Errorf("parse listen address: %w", err)
	}
	ctx, stop := signal.NotifyContext(ctx, os.Interrupt)
	defer stop()

	ep, err := iroh.Bind(ctx, iroh.WithBindAddr(ap))
	if err != nil {
		return err
	}
	defer ep.Shutdown(ctx)
	router, err := iroh.NewRouter(ep, map[string]iroh.ProtocolHandler{
		contentdiscovery.ALPN: contentdiscovery.NewTrackerHandler(contentdiscovery.NewStore(*expiry)),
	}, nil)
	if err != nil {
		return err
	}
	defer router.Shutdown(ctx)

	fmt.Printf("id %s\n", ep.ID())
	fmt.Printf("ip %s\n", ep.LocalAddr())
	<-ctx.Done()
	return nil
}
