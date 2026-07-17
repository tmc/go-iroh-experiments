// SPDX-License-Identifier: Apache-2.0

// Enclave-iroh runs an iroh endpoint whose ed25519 identity is custodied in the
// Apple Secure Enclave, inside the same hardened runtime as the tmc/apple
// secure-enclave demo.
//
// Usage:
//
//	enclave-iroh serve [-tag <id>] [-ephemeral] [-bind <addr>] [-attest-out <f>]
//	enclave-iroh dial  -server <ticket> [-tag <id>] [-ephemeral] [msg...]
//	enclave-iroh verify-attestation <file>
//
// Serve binds an endpoint, prints its ticket, and echoes newline-delimited
// lines back uppercased. Dial connects to a ticket, sends each message, and
// prints the replies. Verify-attestation checks a signed session record on any
// platform.
//
// Before the endpoint key is unwrapped the process hardens itself: it reads the
// kernel's code-signing status via csops, refuses to start under a debugger,
// applies PT_DENY_ATTACH, and polls P_TRACED while running. The endpoint seed
// is ECIES-wrapped to a Secure Enclave P-256 key and only the ciphertext is
// stored, in the Data Protection Keychain; the seed is decrypted in the Enclave
// at startup and zeroed after the endpoint binds.
//
// A persistent identity (-ephemeral=false, the default) needs a keychain
// entitlement: run with -ephemeral for a fresh identity per process under an
// ad-hoc signature, or set MACGO_TEAM_ID to re-exec inside a Developer-ID-signed
// .app with the Hardened Runtime. Hardening and key custody require macOS on
// Apple Silicon or a T2 Mac; -verify-attestation works anywhere.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"net/netip"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/tmc/go-iroh-experiments/enclaveiroh"
	"github.com/tmc/go-iroh/endpointticket"
	"github.com/tmc/go-iroh/iroh"
	"github.com/tmc/go-iroh/key"
)

// hardenedConfig holds the anti-debug and attestation flags shared by the
// endpoint subcommands.
type hardenedConfig struct {
	DenyAttach     bool
	RequireMaximal bool
	TracePoll      time.Duration
	Attest         bool
	AttestOut      string
}

func registerHardenedFlags(fs *flag.FlagSet) *hardenedConfig {
	hcfg := &hardenedConfig{}
	fs.BoolVar(&hcfg.DenyAttach, "deny-attach", true, "call PT_DENY_ATTACH so future debugger attach is refused")
	fs.BoolVar(&hcfg.RequireMaximal, "require-maximal", false, "refuse to run unless the kernel reports a full Hardened Runtime signature")
	fs.DurationVar(&hcfg.TracePoll, "trace-poll", time.Second, "debugger watchdog poll interval while the endpoint runs (0 disables)")
	fs.BoolVar(&hcfg.Attest, "attest", true, "sign a Secure Enclave attestation of the session")
	fs.StringVar(&hcfg.AttestOut, "attest-out", "", "write the attestation JSON to this file instead of stderr")
	return hcfg
}

func usage() {
	fmt.Fprint(os.Stderr, `usage:
	enclave-iroh serve [-tag <id>] [-ephemeral] [-bind <addr>] [-attest-out <f>]
	enclave-iroh dial  -server <ticket> [-tag <id>] [-ephemeral] [msg...]
	enclave-iroh verify-attestation <file>
`)
	os.Exit(2)
}

func main() {
	log.SetFlags(0)
	log.SetPrefix("enclave-iroh: ")
	if len(os.Args) < 2 {
		usage()
	}

	var err error
	switch os.Args[1] {
	case "serve":
		err = runServe(os.Args[2:])
	case "dial":
		err = runDial(os.Args[2:])
	case "verify-attestation":
		if len(os.Args) != 3 {
			usage()
		}
		err = verifyAttestationFile(os.Args[2], os.Stdout)
	default:
		usage()
	}
	if err != nil {
		log.Fatal(err)
	}
}

const defaultTag = "dev.tmc.go-iroh-experiments.enclave-iroh.endpoint"

// keyStore builds a KeyStore from the common -tag / -ephemeral flags.
func keyStore(tag string, ephemeral bool) *enclaveiroh.KeyStore {
	return &enclaveiroh.KeyStore{Tag: tag, Ephemeral: ephemeral}
}

// prepare hardens the process and unwraps the endpoint key, returning the key,
// the hardening report, and a watchdog-stop func. It is the shared front half
// of serve and dial.
func prepare(hcfg *hardenedConfig, tag string, ephemeral bool, report io.Writer) (key.SecretKey, hardeningReport, func(), error) {
	bundled, err := maybeBundle()
	if err != nil {
		return key.SecretKey{}, hardeningReport{}, nil, err
	}
	hr, err := hardenProcess(hcfg, bundled, report)
	if err != nil {
		return key.SecretKey{}, hr, nil, err
	}
	stop := startTraceWatchdog(hcfg.TracePoll)

	sk, err := keyStore(tag, ephemeral).SecretKey()
	if err != nil {
		stop()
		return key.SecretKey{}, hr, nil, fmt.Errorf("endpoint key: %w", err)
	}
	fmt.Fprintf(report, "custody: endpoint key %s (%s)\n", sk.Public().EndpointID(), keyMode(ephemeral))
	return sk, hr, stop, nil
}

func keyMode(ephemeral bool) string {
	if ephemeral {
		return "ephemeral, enclave-wrapped in memory"
	}
	return "persistent, enclave-wrapped in the keychain"
}

func runServe(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	tag := fs.String("tag", defaultTag, "keychain tag identifying the endpoint's Enclave wrapping key")
	ephemeral := fs.Bool("ephemeral", false, "use a fresh in-memory identity (works without a keychain entitlement)")
	bind := fs.String("bind", "[::1]:0", "address to bind (host:port)")
	hcfg := registerHardenedFlags(fs)
	fs.Parse(args)

	report := io.Writer(os.Stderr)
	sk, hr, stop, err := prepare(hcfg, *tag, *ephemeral, report)
	if err != nil {
		return err
	}
	defer stop()

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	ep, err := bindEndpoint(ctx, sk, *bind)
	if err != nil {
		return err
	}
	defer shutdown(ep)

	start := time.Now()
	fmt.Printf("ticket: %s\n", endpointticket.Encode(ep.Addr()))
	fmt.Fprintf(report, "serving echo on %s; Ctrl-C to stop\n", ep.ID())

	errc := make(chan error, 1)
	go func() { errc <- serveEcho(ep, report) }()
	select {
	case <-ctx.Done():
	case err := <-errc:
		if err != nil {
			return err
		}
	}

	if hcfg.Attest {
		att := newAttestation("serve", ep.ID().String(), "", *ephemeral, start, hr)
		if err := attest(att, *tag, *ephemeral, hcfg.AttestOut, report); err != nil {
			return err
		}
	}
	return nil
}

func runDial(args []string) error {
	fs := flag.NewFlagSet("dial", flag.ExitOnError)
	ticket := fs.String("server", "", "server ticket to dial (required)")
	tag := fs.String("tag", defaultTag+".client", "keychain tag identifying the client's Enclave wrapping key")
	ephemeral := fs.Bool("ephemeral", true, "use a fresh in-memory identity (works without a keychain entitlement)")
	bind := fs.String("bind", "[::1]:0", "address to bind (host:port)")
	hcfg := registerHardenedFlags(fs)
	fs.Parse(args)
	if *ticket == "" {
		return fmt.Errorf("dial: -server ticket is required")
	}
	messages := fs.Args()
	if len(messages) == 0 {
		messages = []string{"hello from the enclave"}
	}

	addr, err := endpointticket.Decode(*ticket)
	if err != nil {
		return fmt.Errorf("decode ticket: %w", err)
	}

	report := io.Writer(os.Stderr)
	sk, hr, stop, err := prepare(hcfg, *tag, *ephemeral, report)
	if err != nil {
		return err
	}
	defer stop()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	ep, err := bindEndpoint(ctx, sk, *bind)
	if err != nil {
		return err
	}
	defer shutdown(ep)

	start := time.Now()
	replies, err := dialEcho(ctx, ep, addr, messages)
	for i, r := range replies {
		fmt.Printf("%s -> %s\n", messages[i], r)
	}
	if err != nil {
		return err
	}

	if hcfg.Attest {
		att := newAttestation("dial", ep.ID().String(), addr.ID.String(), *ephemeral, start, hr)
		if err := attest(att, *tag, *ephemeral, hcfg.AttestOut, report); err != nil {
			return err
		}
	}
	return nil
}

// shutdown closes ep with a bounded deadline, for use in defer.
func shutdown(ep *iroh.Endpoint) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = ep.Shutdown(ctx)
}

// bindEndpoint binds an iroh endpoint on addr using sk and the echo ALPN.
func bindEndpoint(ctx context.Context, sk key.SecretKey, addr string) (*iroh.Endpoint, error) {
	ap, err := netip.ParseAddrPort(addr)
	if err != nil {
		return nil, fmt.Errorf("parse -bind %q: %w", addr, err)
	}
	ep, err := iroh.Bind(ctx,
		iroh.WithSecretKey(sk),
		iroh.WithALPNs(alpn),
		iroh.WithBindAddr(ap),
	)
	if err != nil {
		return nil, fmt.Errorf("bind endpoint: %w", err)
	}
	return ep, nil
}

// newAttestation builds an unsigned session attestation.
func newAttestation(role, endpointID, peer string, ephemeral bool, start time.Time, hr hardeningReport) *attestation {
	return &attestation{
		Version:    1,
		Tool:       "enclave-iroh",
		Role:       role,
		EndpointID: endpointID,
		Peer:       peer,
		Ephemeral:  ephemeral,
		Start:      start.UTC().Format(time.RFC3339Nano),
		End:        time.Now().UTC().Format(time.RFC3339Nano),
		Hardening:  hr,
	}
}

// attest signs att with a Secure Enclave key and emits it. The attestation key
// reuses the endpoint tag so a verifier can pin one identity per node; it is
// permanent only when the endpoint identity is.
func attest(att *attestation, tag string, ephemeral bool, out string, report io.Writer) error {
	att.KeyTag = tag + ".attest"
	signer, err := enclaveiroh.NewSigner(att.KeyTag, !ephemeral)
	if err != nil {
		return fmt.Errorf("attestation key: %w", err)
	}
	defer signer.Release()
	if err := signAttestation(att, signer); err != nil {
		return err
	}
	return emitAttestation(att, out, report)
}
