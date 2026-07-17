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
	"strconv"
	"strings"
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

// claimVersion is the operator-asserted monotonic build version signed into
// this binary's claims (Claim.ClaimVersion), or "" for 0. It is set at build
// time so the assertion is bound to the build, not to a runtime flag:
//
//	go build -ldflags "-X main.claimVersion=2" ./cmd/enclave-iroh
//
// Verifiers gate on it with -min-peer-version.
var claimVersion string

// peerConfig holds the T6 attestation-handshake flags: whether to run the
// channel-bound handshake with the peer, and the policy applied to the peer's
// claim.
type peerConfig struct {
	Enable          bool
	Mode            string
	RequireMaximal  bool
	AllowUnattested bool
	MinPeerVersion  uint64
	PinCDHash       string
	PinTeam         string
	PinAttestKey    string
}

func registerPeerFlags(fs *flag.FlagSet) *peerConfig {
	pc := &peerConfig{}
	fs.BoolVar(&pc.Enable, "attest-peer", false, "run the T6 attestation handshake with the peer before app data")
	fs.StringVar(&pc.Mode, "attest-mode", "mutual", `handshake mode: "mutual", "prove", or "verify"`)
	fs.BoolVar(&pc.RequireMaximal, "require-peer-maximal", false, "reject a peer whose code-signing is not maximal")
	fs.BoolVar(&pc.AllowUnattested, "allow-unattested", false, "accept a verify-only peer as an explicit L0 result")
	fs.Uint64Var(&pc.MinPeerVersion, "min-peer-version", 0, "reject a peer whose claim_version is below this")
	fs.StringVar(&pc.PinCDHash, "pin-cdhash", "", "require the peer's cdhash to be this hex value")
	fs.StringVar(&pc.PinTeam, "pin-team", "", "require the peer's signing Team ID to be this value")
	fs.StringVar(&pc.PinAttestKey, "pin-attest-key", "", "require the peer's attestation public key to be this X9.63 hex")
	return pc
}

// mode parses the -attest-mode flag.
func (pc *peerConfig) mode() (enclaveiroh.Mode, error) {
	switch pc.Mode {
	case "mutual":
		return enclaveiroh.ModeMutual, nil
	case "prove":
		return enclaveiroh.ModeProve, nil
	case "verify":
		return enclaveiroh.ModeVerify, nil
	default:
		return 0, fmt.Errorf("-attest-mode must be mutual, prove, or verify (got %q)", pc.Mode)
	}
}

// policy builds the verifier policy from the pin flags.
func (pc *peerConfig) policy() enclaveiroh.Policy {
	p := enclaveiroh.Policy{
		RequireMaximal:  pc.RequireMaximal,
		AllowUnattested: pc.AllowUnattested,
		MinClaimVersion: pc.MinPeerVersion,
	}
	if pc.PinCDHash != "" {
		p.AllowedCDHashes = []string{pc.PinCDHash}
	}
	if pc.PinTeam != "" {
		p.AllowedTeamIDs = []string{pc.PinTeam}
	}
	if pc.PinAttestKey != "" {
		p.PinnedAttestKeys = []string{pc.PinAttestKey}
	}
	return p
}

func usage() {
	fmt.Fprint(os.Stderr, `usage:
	enclave-iroh serve [-tag <id>] [-ephemeral] [-bind <addr>] [-attest-out <f>] [-attest-peer [-attest-mode <m>] [policy flags]]
	enclave-iroh dial  -server <ticket> [-tag <id>] [-ephemeral] [-attest-peer [-attest-mode <m>] [policy flags]] [msg...]
	enclave-iroh verify-attestation <file>

Run "enclave-iroh serve -h" or "enclave-iroh dial -h" for the full flag set,
including -attest-peer and its policy flags (-require-peer-maximal, -pin-cdhash,
-pin-team, -pin-attest-key, -min-peer-version, -allow-unattested).
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
	pc := registerPeerFlags(fs)
	fs.Parse(args)

	report := io.Writer(os.Stderr)
	sk, hr, stop, err := prepare(hcfg, *tag, *ephemeral, report)
	if err != nil {
		return err
	}
	defer stop()

	signer, keyTag, err := runSigner(hcfg, pc, *tag, *ephemeral)
	if err != nil {
		return err
	}
	if signer != nil {
		defer signer.Release()
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	ep, err := bindEndpoint(ctx, sk, *bind)
	if err != nil {
		return err
	}
	defer shutdown(ep)

	hsCfg, err := newHandshakeConfig(pc, ep.ID(), signer, hr, *ephemeral, report)
	if err != nil {
		return err
	}

	start := time.Now()
	fmt.Printf("ticket: %s\n", endpointticket.Encode(ep.Addr()))
	fmt.Fprintf(report, "serving echo on %s; Ctrl-C to stop\n", ep.ID())
	if hsCfg != nil {
		fmt.Fprintf(report, "attest: requiring T6 handshake (mode %s) from every peer\n", pc.Mode)
	}

	errc := make(chan error, 1)
	go func() { errc <- serveEcho(ctx, ep, report, hsCfg) }()
	select {
	case <-ctx.Done():
	case err := <-errc:
		if err != nil {
			return err
		}
	}

	if hcfg.Attest {
		att := newAttestation("serve", ep.ID().String(), "", *ephemeral, start, hr)
		if err := attest(att, signer, keyTag, hcfg.AttestOut, report); err != nil {
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
	pc := registerPeerFlags(fs)
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

	signer, keyTag, err := runSigner(hcfg, pc, *tag, *ephemeral)
	if err != nil {
		return err
	}
	if signer != nil {
		defer signer.Release()
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	ep, err := bindEndpoint(ctx, sk, *bind)
	if err != nil {
		return err
	}
	defer shutdown(ep)

	hsCfg, err := newHandshakeConfig(pc, ep.ID(), signer, hr, *ephemeral, report)
	if err != nil {
		return err
	}

	conn, err := ep.Connect(ctx, addr, alpn)
	if err != nil {
		return fmt.Errorf("connect: %w", err)
	}
	defer conn.Close()

	start := time.Now()
	var peerAtt *enclaveiroh.PeerAttestation
	if hsCfg != nil {
		peerAtt, err = enclaveiroh.Handshake(ctx, conn, *hsCfg)
		if err != nil {
			return fmt.Errorf("peer attestation: %w", err)
		}
		logPeerAttestation(report, conn.RemoteID(), peerAtt)
	}

	replies, err := echoOverConn(ctx, conn, messages)
	for i, r := range replies {
		fmt.Printf("%s -> %s\n", messages[i], r)
	}
	if err != nil {
		return err
	}

	if hcfg.Attest {
		att := newAttestation("dial", ep.ID().String(), addr.ID.String(), *ephemeral, start, hr)
		if hsCfg != nil {
			// A handshake ran, so peer attestation is a property of this 1:1
			// record: true with the verified Claim, or false for an L0 peer.
			attested := peerAtt != nil && peerAtt.Attested
			att.PeerAttested = &attested
			if attested {
				att.PeerClaim = &peerAtt.Claim
			}
		}
		if err := attest(att, signer, keyTag, hcfg.AttestOut, report); err != nil {
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

// attest signs att with the shared Secure Enclave signer and emits it.
func attest(att *attestation, signer enclaveiroh.Signer, keyTag, out string, report io.Writer) error {
	att.KeyTag = keyTag
	if err := signAttestation(att, signer); err != nil {
		return err
	}
	return emitAttestation(att, out, report)
}

// runSigner creates the one Secure Enclave signer a run needs: a single
// attestation key, keyed off the endpoint tag, that signs both the session
// record and the handshake claims. It returns a nil signer when nothing needs
// signing (no session record and a verify-only handshake). The key is permanent
// only when the endpoint identity is.
func runSigner(hcfg *hardenedConfig, pc *peerConfig, tag string, ephemeral bool) (enclaveiroh.Signer, string, error) {
	needRecord := hcfg.Attest
	needPeer := pc.Enable && pc.Mode != "verify"
	if !needRecord && !needPeer {
		return nil, "", nil
	}
	keyTag := tag + ".attest"
	signer, err := enclaveiroh.NewSigner(keyTag, !ephemeral)
	if err != nil {
		return nil, "", fmt.Errorf("attestation key: %w", err)
	}
	return signer, keyTag, nil
}

// newHandshakeConfig builds the T6 handshake config for a run, or nil when
// -attest-peer is off. signer may be nil for a verify-only handshake. It warns
// to report when peer-policy flags are set in a mode that never evaluates the
// peer, so a user does not believe they enforced a policy that is inert.
func newHandshakeConfig(pc *peerConfig, selfID key.EndpointID, signer enclaveiroh.Signer, hr hardeningReport, ephemeral bool, report io.Writer) (*enclaveiroh.HandshakeConfig, error) {
	if !pc.Enable {
		return nil, nil
	}
	mode, err := pc.mode()
	if err != nil {
		return nil, err
	}
	if mode == enclaveiroh.ModeProve {
		if inert := pc.inertPolicyFlags(); len(inert) > 0 {
			fmt.Fprintf(report, "attest: warning: -attest-mode prove does not evaluate the peer; %s ignored\n",
				strings.Join(inert, ", "))
		}
	}
	var id enclaveiroh.CodeIdentity
	if mode != enclaveiroh.ModeVerify {
		id, err = enclaveiroh.LocalCodeIdentity()
		if err != nil {
			return nil, fmt.Errorf("local code identity: %w", err)
		}
	}
	ver, err := parseClaimVersion()
	if err != nil {
		return nil, err
	}
	return &enclaveiroh.HandshakeConfig{
		SelfID:       selfID,
		Mode:         mode,
		Signer:       signer,
		Identity:     id,
		Bundled:      hr.Bundled,
		EphemeralKey: ephemeral,
		ClaimVersion: ver,
		Policy:       pc.policy(),
	}, nil
}

// parseClaimVersion parses the build-time claimVersion ldflags var; unset is 0.
func parseClaimVersion() (uint64, error) {
	if claimVersion == "" {
		return 0, nil
	}
	v, err := strconv.ParseUint(claimVersion, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("build-time claimVersion %q is not an unsigned integer: %w", claimVersion, err)
	}
	return v, nil
}

// inertPolicyFlags returns the names of the peer-policy flags that were set but
// have no effect because the handshake mode never verifies the peer's Claim.
func (pc *peerConfig) inertPolicyFlags() []string {
	var inert []string
	if pc.RequireMaximal {
		inert = append(inert, "-require-peer-maximal")
	}
	if pc.AllowUnattested {
		inert = append(inert, "-allow-unattested")
	}
	if pc.MinPeerVersion > 0 {
		inert = append(inert, "-min-peer-version")
	}
	if pc.PinCDHash != "" {
		inert = append(inert, "-pin-cdhash")
	}
	if pc.PinTeam != "" {
		inert = append(inert, "-pin-team")
	}
	if pc.PinAttestKey != "" {
		inert = append(inert, "-pin-attest-key")
	}
	return inert
}

// logPeerAttestation reports the outcome of a peer handshake.
func logPeerAttestation(report io.Writer, peerID key.EndpointID, att *enclaveiroh.PeerAttestation) {
	switch {
	case att == nil:
		fmt.Fprintf(report, "attest: %s — proved our identity (peer not evaluated)\n", peerID)
	case !att.Attested:
		fmt.Fprintf(report, "attest: %s — accepted unattested (L0)\n", peerID)
	default:
		max := enclaveiroh.MaximalFlags(att.Claim.CSFlags)
		fmt.Fprintf(report, "attest: %s VERIFIED — cdhash %s team %q maximal=%v\n",
			peerID, shortHash(att.Claim.CDHash), att.Claim.TeamID, max)
	}
}

func shortHash(h string) string {
	if len(h) > 16 {
		return h[:16] + "…"
	}
	if h == "" {
		return "(none)"
	}
	return h
}
