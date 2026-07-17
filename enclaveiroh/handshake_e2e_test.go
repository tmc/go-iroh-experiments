package enclaveiroh

import (
	"bufio"
	"context"
	"encoding/hex"
	"fmt"
	"net/netip"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/tmc/go-iroh/iroh"
	"github.com/tmc/go-iroh/netaddr"
)

// These tests cover the iroh-transport integration of the handshake: a real
// Endpoint loopback, the first-stream-is-the-handshake ordering, and app
// streams flowing after it. The protocol layer itself is covered over net.Pipe
// in handshake_test.go.

const e2eALPN = "enclaveiroh/e2e/1"

// e2eIdentity is a synthetic code identity for portable tests; the darwin
// Enclave test uses the real one.
func e2eIdentity(team string) CodeIdentity {
	cd := make([]byte, 20)
	for i := range cd {
		cd[i] = byte(i)
	}
	return CodeIdentity{CDHash: cd, TeamID: team, SigningID: "e2e.test", Flags: CSValid | CSKill}
}

// connectPair binds two endpoints on the IPv6 loopback and returns the client
// and server side of one connection between them.
func connectPair(t *testing.T, ctx context.Context) (client, server *iroh.Conn) {
	t.Helper()
	bind := func(name string) *iroh.Endpoint {
		ep, err := iroh.Bind(ctx,
			iroh.WithBindAddr(netip.AddrPortFrom(netip.IPv6Loopback(), 0)),
			iroh.WithALPNs(e2eALPN),
		)
		if err != nil {
			t.Skipf("bind endpoint %s: %v", name, err)
		}
		t.Cleanup(func() { shutdownEndpoint(ep) })
		return ep
	}
	epA, epB := bind("A"), bind("B")

	accepted := make(chan *iroh.Conn, 1)
	errc := make(chan error, 1)
	go func() {
		conn, err := epB.Accept(ctx)
		if err != nil {
			errc <- err
			return
		}
		accepted <- conn
	}()
	var err error
	client, err = epA.Connect(ctx, netaddr.NewEndpointAddr(epB.ID()).WithIP(epB.LocalAddr()), e2eALPN)
	if err != nil {
		t.Fatalf("Connect() = %v", err)
	}
	select {
	case server = <-accepted:
	case err := <-errc:
		t.Fatalf("Accept() = %v", err)
	case <-ctx.Done():
		t.Fatal("timed out waiting for Accept")
	}
	return client, server
}

// runBothSides runs the handshake concurrently on both conns and returns each
// side's outcome.
func runBothSides(ctx context.Context, client, server *iroh.Conn, clientCfg, serverCfg HandshakeConfig) (clientAtt, serverAtt *PeerAttestation, clientErr, serverErr error) {
	done := make(chan struct{})
	go func() {
		defer close(done)
		serverAtt, serverErr = Handshake(ctx, server, serverCfg)
	}()
	clientAtt, clientErr = Handshake(ctx, client, clientCfg)
	<-done
	return clientAtt, serverAtt, clientErr, serverErr
}

func TestHandshakeOverIroh(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	client, server := connectPair(t, ctx)

	// SelfID is each side's own endpoint ID: the client's is what the server
	// sees as RemoteID, and vice versa.
	clientCfg := HandshakeConfig{
		SelfID: server.RemoteID(), Mode: ModeMutual,
		Signer: newFakeSigner(t), Identity: e2eIdentity("CLIENTTEAM"),
		ClaimVersion: 7,
		Policy:       Policy{MinClaimVersion: 3}, // server claims 3: at threshold
	}
	serverCfg := HandshakeConfig{
		SelfID: client.RemoteID(), Mode: ModeMutual,
		Signer: newFakeSigner(t), Identity: e2eIdentity("SERVERTEAM"),
		ClaimVersion: 3,
	}

	clientAtt, serverAtt, clientErr, serverErr := runBothSides(ctx, client, server, clientCfg, serverCfg)
	if clientErr != nil || serverErr != nil {
		t.Fatalf("Handshake errors: client=%v server=%v", clientErr, serverErr)
	}
	if clientAtt == nil || !clientAtt.Attested || serverAtt == nil || !serverAtt.Attested {
		t.Fatalf("attestations: client=%+v server=%+v, want both Attested", clientAtt, serverAtt)
	}
	if clientAtt.Claim.ClaimVersion != 3 || serverAtt.Claim.ClaimVersion != 7 {
		t.Errorf("claim versions: client saw %d (want 3), server saw %d (want 7)",
			clientAtt.Claim.ClaimVersion, serverAtt.Claim.ClaimVersion)
	}

	// Cross-check the channel binding from each side's view.
	if got := clientAtt.Claim.Role; got != RoleServe {
		t.Errorf("client saw peer role %q, want %q", got, RoleServe)
	}
	if got := serverAtt.Claim.Role; got != RoleDial {
		t.Errorf("server saw peer role %q, want %q", got, RoleDial)
	}
	if got, want := clientAtt.Claim.LocalEndpoint, client.RemoteID().String(); got != want {
		t.Errorf("client saw peer endpoint %s, want %s", got, want)
	}
	if got, want := clientAtt.Claim.CDHash, hex.EncodeToString(e2eIdentity("SERVERTEAM").CDHash); got != want {
		t.Errorf("client saw peer cdhash %s, want %s", got, want)
	}
	if got := clientAtt.Claim.TeamID; got != "SERVERTEAM" {
		t.Errorf("client saw peer team %q, want SERVERTEAM", got)
	}

	// The handshake consumed the first bidirectional stream; application
	// streams flow after it.
	appStream, err := client.OpenStreamConn(ctx)
	if err != nil {
		t.Fatalf("open app stream: %v", err)
	}
	defer appStream.Close()
	echoErr := make(chan error, 1)
	go func() {
		s, err := server.AcceptStreamConn(ctx)
		if err != nil {
			echoErr <- err
			return
		}
		defer s.Close()
		line, err := bufio.NewReader(s).ReadString('\n')
		if err != nil {
			echoErr <- err
			return
		}
		_, err = s.Write([]byte(strings.ToUpper(line)))
		echoErr <- err
	}()
	if _, err := fmt.Fprintln(appStream, "attested ping"); err != nil {
		t.Fatalf("write app stream: %v", err)
	}
	reply, err := bufio.NewReader(appStream).ReadString('\n')
	if err != nil {
		t.Fatalf("read app stream: %v", err)
	}
	if reply != "ATTESTED PING\n" {
		t.Fatalf("app stream reply %q, want %q", reply, "ATTESTED PING\n")
	}
	if err := <-echoErr; err != nil {
		t.Fatalf("server echo: %v", err)
	}
}

func TestHandshakePolicyRejectOverIroh(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	client, server := connectPair(t, ctx)

	clientCfg := HandshakeConfig{
		SelfID: server.RemoteID(), Mode: ModeMutual,
		Signer: newFakeSigner(t), Identity: e2eIdentity("CLIENTTEAM"), // ad-hoc flags
	}
	serverCfg := HandshakeConfig{
		SelfID: client.RemoteID(), Mode: ModeMutual,
		Signer: newFakeSigner(t), Identity: e2eIdentity("SERVERTEAM"),
		Policy: Policy{RequireMaximal: true},
	}

	_, _, clientErr, serverErr := runBothSides(ctx, client, server, clientCfg, serverCfg)
	if serverErr == nil || !strings.Contains(serverErr.Error(), "not maximal") {
		t.Fatalf("server Handshake() = %v, want a not-maximal policy rejection", serverErr)
	}
	// The Result is advisory: the client's own verdict over the server's claim
	// is what the client gets, and the server's claim passed the client's
	// (empty) policy.
	if clientErr != nil {
		t.Fatalf("client Handshake() = %v, want nil (rejection is server-side)", clientErr)
	}
}

func TestHandshakeVerifyOnlyOverIroh(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	client, server := connectPair(t, ctx)

	// Client cannot attest (no Enclave, mode verify); server proves.
	clientCfg := HandshakeConfig{SelfID: server.RemoteID(), Mode: ModeVerify}
	serverCfg := HandshakeConfig{
		SelfID: client.RemoteID(), Mode: ModeProve,
		Signer: newFakeSigner(t), Identity: e2eIdentity("SERVERTEAM"),
	}

	clientAtt, serverAtt, clientErr, serverErr := runBothSides(ctx, client, server, clientCfg, serverCfg)
	if clientErr != nil || serverErr != nil {
		t.Fatalf("Handshake errors: client=%v server=%v", clientErr, serverErr)
	}
	if clientAtt == nil || !clientAtt.Attested {
		t.Fatalf("client attestation = %+v, want Attested (server proved)", clientAtt)
	}
	// A prove-only side verifies nothing; its result is nil.
	if serverAtt != nil {
		t.Fatalf("server attestation = %+v, want nil for prove-only", serverAtt)
	}
}

// TestHandshakeEnclaveOverIroh runs the full native chain on a Secure Enclave:
// both sides sign with ephemeral Enclave keys and report the real code
// identity, and each verifies the other with the portable stdlib path. Both
// sides run in one process, so each side must see its own cdhash from the
// peer.
func TestHandshakeEnclaveOverIroh(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("Secure Enclave signing requires macOS")
	}
	identity, err := LocalCodeIdentity()
	if err != nil {
		t.Fatalf("LocalCodeIdentity() = %v", err)
	}
	clientSigner, err := NewSigner("enclaveiroh.test.e2e.client", false)
	if err != nil {
		t.Skipf("no usable Secure Enclave here: %v", err)
	}
	defer clientSigner.Release()
	serverSigner, err := NewSigner("enclaveiroh.test.e2e.server", false)
	if err != nil {
		t.Skipf("no usable Secure Enclave here: %v", err)
	}
	defer serverSigner.Release()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	client, server := connectPair(t, ctx)

	clientCfg := HandshakeConfig{
		SelfID: server.RemoteID(), Mode: ModeMutual,
		Signer: clientSigner, Identity: identity, EphemeralKey: true,
	}
	serverCfg := HandshakeConfig{
		SelfID: client.RemoteID(), Mode: ModeMutual,
		Signer: serverSigner, Identity: identity, EphemeralKey: true,
	}

	clientAtt, serverAtt, clientErr, serverErr := runBothSides(ctx, client, server, clientCfg, serverCfg)
	if clientErr != nil || serverErr != nil {
		t.Fatalf("Handshake errors: client=%v server=%v", clientErr, serverErr)
	}
	if clientAtt == nil || !clientAtt.Attested || serverAtt == nil || !serverAtt.Attested {
		t.Fatalf("attestations: client=%+v server=%+v, want both Attested", clientAtt, serverAtt)
	}
	want := hex.EncodeToString(identity.CDHash)
	if clientAtt.Claim.CDHash != want || serverAtt.Claim.CDHash != want {
		t.Fatalf("peer cdhashes %s / %s, want both %s (same process)",
			clientAtt.Claim.CDHash, serverAtt.Claim.CDHash, want)
	}
}

func shutdownEndpoint(ep *iroh.Endpoint) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = ep.Shutdown(ctx)
}
