// Groupchat runs a two-member MLS chat with a sole committing owner.
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/netip"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/tmc/go-iroh/iroh"
	"github.com/tmc/go-iroh/key"
)

func main() {
	log.SetFlags(0)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := command(ctx, os.Args[1:], os.Stdin, os.Stdout); err != nil && ctx.Err() == nil {
		log.Fatal(err)
	}
}

func command(ctx context.Context, args []string, in io.Reader, out io.Writer) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: groupchat identity|owner|member|demo [flags]")
	}
	if args[0] == "demo" {
		return runDemo()
	}
	f := flag.NewFlagSet(args[0], flag.ContinueOnError)
	name := f.String("key", "", "endpoint key file (created with mode 0600)")
	invite := f.String("invite", "", "invitation file")
	allow := f.String("allow", "", "member endpoint ID to invite")
	bind := f.String("bind", "127.0.0.1:0", "direct UDP bind address")
	if err := f.Parse(args[1:]); err != nil {
		return err
	}
	if f.NArg() != 0 {
		return fmt.Errorf("unexpected arguments")
	}
	if *name == "" {
		return fmt.Errorf("-key is required")
	}
	sk, err := loadKey(*name)
	if err != nil {
		return err
	}
	if args[0] == "identity" {
		fmt.Fprintln(out, sk.Public().EndpointID())
		return nil
	}
	if args[0] != "owner" && args[0] != "member" {
		return fmt.Errorf("unknown command %q", args[0])
	}
	if *invite == "" {
		return fmt.Errorf("-invite is required")
	}
	ap, err := netip.ParseAddrPort(*bind)
	if err != nil {
		return err
	}
	ep, err := iroh.Bind(ctx, iroh.WithSecretKey(sk), iroh.WithBindAddr(ap))
	if err != nil {
		return err
	}
	defer ep.Shutdown(context.Background())
	if args[0] == "owner" {
		id, err := key.ParseEndpointID(*allow)
		if err != nil {
			return fmt.Errorf("-allow: %w", err)
		}
		return runOwner(ctx, ep, sk, id, *invite, in, out)
	}
	return runMember(ctx, ep, sk, *invite, in, out)
}

func loadKey(name string) (key.SecretKey, error) {
	b, err := os.ReadFile(name)
	if err == nil {
		return key.SecretKeyFromSlice(b)
	}
	if !os.IsNotExist(err) {
		return key.SecretKey{}, err
	}
	sk, err := key.GenerateSecretKey()
	if err != nil {
		return sk, err
	}
	f, err := os.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return key.SecretKey{}, err
	}
	seed := sk.Bytes()
	_, err = f.Write(seed[:])
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err == nil {
		err = closeErr
	}
	return sk, err
}

type inputLine struct {
	text string
	err  error
}

func input(ctx context.Context, r io.Reader) <-chan inputLine {
	ch := make(chan inputLine)
	go func() {
		defer close(ch)
		s := bufio.NewScanner(r)
		s.Buffer(make([]byte, 4096), 16<<10)
		for s.Scan() {
			select {
			case ch <- inputLine{text: strings.TrimSpace(s.Text())}:
			case <-ctx.Done():
				return
			}
		}
		if err := s.Err(); err != nil {
			select {
			case ch <- inputLine{err: err}:
			case <-ctx.Done():
			}
		}
	}()
	return ch
}

func readJSON(r io.Reader, v any) error {
	b, err := io.ReadAll(io.LimitReader(r, maxMessage+1))
	if err != nil {
		return err
	}
	if len(b) > maxMessage {
		return fmt.Errorf("message too large")
	}
	return json.Unmarshal(b, v)
}

func deadline(ctx context.Context) time.Time {
	d := time.Now().Add(3 * time.Second)
	if end, ok := ctx.Deadline(); ok && end.Before(d) {
		return end
	}
	return d
}
