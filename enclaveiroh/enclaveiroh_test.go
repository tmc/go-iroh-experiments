package enclaveiroh_test

import (
	"context"
	"errors"
	"runtime"
	"testing"
	"time"

	"github.com/tmc/go-iroh-experiments/enclaveiroh"
	"github.com/tmc/go-iroh/iroh"
	"github.com/tmc/go-iroh/key"
)

// TestKeyStoreUnsupported checks that off macOS every operation reports
// ErrUnsupported rather than panicking or returning a zero key.
func TestKeyStoreUnsupported(t *testing.T) {
	if runtime.GOOS == "darwin" {
		t.Skip("darwin has a Secure Enclave; unsupported path does not apply")
	}
	ks := &enclaveiroh.KeyStore{Tag: "test"}
	if _, err := ks.SecretKey(); !errors.Is(err, enclaveiroh.ErrUnsupported) {
		t.Fatalf("SecretKey() error = %v, want ErrUnsupported", err)
	}
	if _, err := enclaveiroh.NewSigner("test", false); !errors.Is(err, enclaveiroh.ErrUnsupported) {
		t.Fatalf("NewSigner() error = %v, want ErrUnsupported", err)
	}
}

// TestKeyStoreRequiresTag checks the zero-value guard on all platforms.
func TestKeyStoreRequiresTag(t *testing.T) {
	if _, err := (&enclaveiroh.KeyStore{}).SecretKey(); err == nil {
		t.Fatal("SecretKey() with empty Tag = nil error, want a Tag-required error")
	}
}

// TestEphemeralEndpoint exercises the full custody path on a Secure Enclave: it
// wraps a fresh ed25519 seed to an ephemeral Enclave P-256 key, unwraps it, and
// binds an iroh endpoint whose identity matches the unwrapped key. It is skipped
// on machines without an Enclave.
func TestEphemeralEndpoint(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("Secure Enclave key custody requires macOS")
	}
	ks := &enclaveiroh.KeyStore{Tag: "enclaveiroh.test.ephemeral", Ephemeral: true}
	sk, err := ks.SecretKey()
	if err != nil {
		t.Skipf("no usable Secure Enclave here: %v", err)
	}
	if sk.Public().EndpointID() == (key.EndpointID{}) {
		t.Fatal("SecretKey() returned the zero identity")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	ep, err := iroh.Bind(ctx, iroh.WithSecretKey(sk), iroh.WithALPNs("enclaveiroh/test/1"))
	if err != nil {
		t.Fatalf("Bind() = %v", err)
	}
	defer ep.Shutdown(ctx)

	if ep.ID() != sk.Public().EndpointID() {
		t.Fatalf("endpoint ID %s does not match custodied key %s", ep.ID(), sk.Public().EndpointID())
	}
}

// TestSignerRoundTrip checks that an ephemeral Enclave signer signs and
// self-verifies, and rejects a corrupted signature.
func TestSignerRoundTrip(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("Secure Enclave signing requires macOS")
	}
	signer, err := enclaveiroh.NewSigner("enclaveiroh.test.signer", false)
	if err != nil {
		t.Skipf("no usable Secure Enclave here: %v", err)
	}
	defer signer.Release()

	msg := []byte("attest me")
	sig, err := signer.Sign(msg)
	if err != nil {
		t.Fatalf("Sign() = %v", err)
	}
	ok, err := signer.Verify(msg, sig)
	if err != nil {
		t.Fatalf("Verify() = %v", err)
	}
	if !ok {
		t.Fatal("Verify() = false for a genuine signature")
	}
	sig[len(sig)-1] ^= 0xff
	ok, err = signer.Verify(msg, sig)
	if err != nil {
		t.Fatalf("Verify(corrupted) = %v", err)
	}
	if ok {
		t.Fatal("Verify() = true for a corrupted signature")
	}
}
