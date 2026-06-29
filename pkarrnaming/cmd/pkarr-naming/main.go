package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	"github.com/tmc/go-iroh-experiments/pkarrnaming"
	"github.com/tmc/go-iroh/key"
)

func main() {
	if err := run(context.Background(), os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
}

func run(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return usage()
	}
	switch args[0] {
	case "publish":
		return runPublish(ctx, args[1:])
	case "resolve":
		return runResolve(ctx, args[1:])
	default:
		return usage()
	}
}

func runPublish(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("publish", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	relay := fs.String("relay", pkarrnaming.DefaultRelayURL, "pkarr relay URL")
	ttl := fs.Uint("ttl", uint(pkarrnaming.DefaultTTL), "record TTL in seconds")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 2 {
		return fmt.Errorf("usage: pkarr-naming publish [--relay=url] [--ttl=seconds] secret-key content-hash")
	}
	sk, err := key.ParseSecretKey(fs.Arg(0))
	if err != nil {
		return fmt.Errorf("parse secret key: %w", err)
	}
	record, err := pkarrnaming.ParseRecord(fs.Arg(1))
	if err != nil {
		return err
	}
	client, err := pkarrnaming.NewRelayClient(*relay, pkarrnaming.WithTTL(uint32(*ttl)))
	if err != nil {
		return err
	}
	if err := client.Publish(ctx, sk, record); err != nil {
		return err
	}
	fmt.Println(sk.Public().String())
	return nil
}

func runResolve(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("resolve", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	relay := fs.String("relay", pkarrnaming.DefaultRelayURL, "pkarr relay URL")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return fmt.Errorf("usage: pkarr-naming resolve [--relay=url] public-key")
	}
	pk, err := key.ParsePublicKey(fs.Arg(0))
	if err != nil {
		return fmt.Errorf("parse public key: %w", err)
	}
	client, err := pkarrnaming.NewRelayClient(*relay)
	if err != nil {
		return err
	}
	record, err := client.Resolve(ctx, pk)
	if err != nil {
		return err
	}
	fmt.Println(pkarrnaming.RecordString(record))
	return nil
}

func usage() error {
	return fmt.Errorf("usage: pkarr-naming publish|resolve")
}
