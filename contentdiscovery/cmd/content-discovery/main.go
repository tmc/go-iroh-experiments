package main

import (
	"context"
	"flag"
	"fmt"
	"net/netip"
	"os"
	"strings"

	"github.com/tmc/go-iroh-experiments/contentdiscovery"
	"github.com/tmc/go-iroh/blobs"
	"github.com/tmc/go-iroh/iroh"
	"github.com/tmc/go-iroh/key"
	"github.com/tmc/go-iroh/netaddr"
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
	case "announce":
		return runAnnounce(ctx, args[1:])
	case "query":
		return runQuery(ctx, args[1:])
	default:
		return usage()
	}
}

func runAnnounce(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("announce", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	trackerID := fs.String("tracker-id", "", "tracker endpoint id")
	trackerIP := fs.String("tracker-ip", "", "tracker ip:port")
	kind := fs.String("kind", "complete", "announce kind: partial or complete")
	format := fs.String("format", "raw", "blob format: raw or hashseq")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 2 {
		return fmt.Errorf("usage: content-discovery announce --tracker-id=id --tracker-ip=ip:port secret-key hash")
	}
	tracker, err := parseTracker(*trackerID, *trackerIP)
	if err != nil {
		return err
	}
	sk, err := key.ParseSecretKey(fs.Arg(0))
	if err != nil {
		return fmt.Errorf("parse secret key: %w", err)
	}
	content, err := parseContent(fs.Arg(1), *format)
	if err != nil {
		return err
	}
	k, err := parseKind(*kind)
	if err != nil {
		return err
	}
	ep, err := iroh.Bind(ctx)
	if err != nil {
		return err
	}
	defer ep.Shutdown(ctx)
	if err := contentdiscovery.NewClient(ep).Announce(ctx, tracker, sk, content, k); err != nil {
		return err
	}
	return nil
}

func runQuery(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("query", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	trackerID := fs.String("tracker-id", "", "tracker endpoint id")
	trackerIP := fs.String("tracker-ip", "", "tracker ip:port")
	format := fs.String("format", "raw", "blob format: raw or hashseq")
	complete := fs.Bool("complete", false, "return only complete announces")
	verified := fs.Bool("verified", true, "return only verified announces")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return fmt.Errorf("usage: content-discovery query --tracker-id=id --tracker-ip=ip:port hash")
	}
	tracker, err := parseTracker(*trackerID, *trackerIP)
	if err != nil {
		return err
	}
	content, err := parseContent(fs.Arg(0), *format)
	if err != nil {
		return err
	}
	ep, err := iroh.Bind(ctx)
	if err != nil {
		return err
	}
	defer ep.Shutdown(ctx)
	hosts, err := contentdiscovery.NewClient(ep).Query(ctx, tracker, content, contentdiscovery.QueryFlags{
		Complete: *complete,
		Verified: *verified,
	})
	if err != nil {
		return err
	}
	for _, h := range hosts {
		fmt.Printf("%s %s %s %d\n", h.Announce.Host, h.Announce.Content.Hash, h.Announce.Kind, h.Announce.Timestamp)
	}
	return nil
}

func parseTracker(idText, ipText string) (netaddr.EndpointAddr, error) {
	if idText == "" || ipText == "" {
		return netaddr.EndpointAddr{}, fmt.Errorf("tracker-id and tracker-ip are required")
	}
	id, err := key.ParseEndpointID(idText)
	if err != nil {
		return netaddr.EndpointAddr{}, fmt.Errorf("parse tracker id: %w", err)
	}
	ap, err := netip.ParseAddrPort(ipText)
	if err != nil {
		return netaddr.EndpointAddr{}, fmt.Errorf("parse tracker ip: %w", err)
	}
	return netaddr.NewEndpointAddr(id).WithIP(ap), nil
}

func parseContent(hashText, formatText string) (blobs.HashAndFormat, error) {
	h, err := blobs.ParseHash(hashText)
	if err != nil {
		return blobs.HashAndFormat{}, fmt.Errorf("parse hash: %w", err)
	}
	switch strings.ToLower(formatText) {
	case "raw":
		return blobs.RawHash(h), nil
	case "hashseq", "seq":
		return blobs.HashSeqHash(h), nil
	default:
		return blobs.HashAndFormat{}, fmt.Errorf("unknown format %q", formatText)
	}
}

func parseKind(s string) (contentdiscovery.AnnounceKind, error) {
	switch strings.ToLower(s) {
	case "partial":
		return contentdiscovery.AnnouncePartial, nil
	case "complete":
		return contentdiscovery.AnnounceComplete, nil
	default:
		return 0, fmt.Errorf("unknown announce kind %q", s)
	}
}

func usage() error {
	return fmt.Errorf("usage: content-discovery announce|query")
}
