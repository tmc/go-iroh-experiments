package enclaveiroh

import (
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// The TOFU semantics under test: first contact records, a matching later
// claim passes, a changed attestation key is rejected, and endpoints are
// independent. What TOFU cannot catch — impersonation on first contact — is
// visible here too: the first Pin always succeeds.

func testPeerClaim(endpoint, attestKey string) Claim {
	return Claim{
		Context:       ClaimContext,
		LocalEndpoint: endpoint,
		AttestKey:     attestKey,
		CDHash:        strings.Repeat("ab", 20),
	}
}

func TestKnownPeersPin(t *testing.T) {
	path := filepath.Join(t.TempDir(), "known-peers.json")
	kp, err := LoadKnownPeers(path)
	if err != nil {
		t.Fatalf("LoadKnownPeers() = %v", err)
	}

	alice := testPeerClaim("endpoint-alice", strings.Repeat("aa", 65))
	bob := testPeerClaim("endpoint-bob", strings.Repeat("bb", 65))

	if err := kp.Pin(alice); err != nil {
		t.Fatalf("first contact: Pin() = %v", err)
	}
	if err := kp.Pin(alice); err != nil {
		t.Fatalf("repeat contact, same key: Pin() = %v", err)
	}
	if err := kp.Pin(bob); err != nil {
		t.Fatalf("independent endpoint: Pin() = %v", err)
	}

	rotated := alice
	rotated.AttestKey = strings.Repeat("cc", 65)
	if err := kp.Pin(rotated); err == nil {
		t.Fatal("Pin() = nil for a changed attestation key, want rejection")
	}

	// A rebuild changes the cdhash but not the key: recorded, not enforced.
	rebuilt := alice
	rebuilt.CDHash = strings.Repeat("dd", 20)
	if err := kp.Pin(rebuilt); err != nil {
		t.Fatalf("same key, new cdhash: Pin() = %v, want nil", err)
	}

	// Pins survive a reload from disk.
	kp2, err := LoadKnownPeers(path)
	if err != nil {
		t.Fatalf("reload: LoadKnownPeers() = %v", err)
	}
	if err := kp2.Pin(alice); err != nil {
		t.Fatalf("after reload, same key: Pin() = %v", err)
	}
	if err := kp2.Pin(rotated); err == nil {
		t.Fatal("after reload, Pin() = nil for a changed key, want rejection")
	}
}

func TestKnownPeersAsPolicy(t *testing.T) {
	kp, err := LoadKnownPeers(filepath.Join(t.TempDir(), "known-peers.json"))
	if err != nil {
		t.Fatalf("LoadKnownPeers() = %v", err)
	}
	p := Policy{PinPeer: kp.Pin}

	first := testPeerClaim("endpoint-carol", strings.Repeat("aa", 65))
	if err := p.Check(first); err != nil {
		t.Fatalf("first contact via Policy.Check: %v", err)
	}
	rotated := first
	rotated.AttestKey = strings.Repeat("ee", 65)
	if err := p.Check(rotated); err == nil {
		t.Fatal("Policy.Check() = nil for a rotated key, want rejection")
	}
}

// TestKnownPeersConcurrentPin drives Pin from concurrent goroutines, the way
// a server's per-connection handshakes share one store. Run under -race this
// exercises the mutex, so the doc comment's concurrency claim is tested, not
// just true by construction.
func TestKnownPeersConcurrentPin(t *testing.T) {
	path := filepath.Join(t.TempDir(), "known-peers.json")
	kp, err := LoadKnownPeers(path)
	if err != nil {
		t.Fatalf("LoadKnownPeers() = %v", err)
	}
	c := testPeerClaim("endpoint-erin", strings.Repeat("aa", 65))

	errs := make([]error, 16)
	var wg sync.WaitGroup
	for i := range errs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs[i] = kp.Pin(c)
		}()
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Errorf("concurrent Pin %d = %v", i, err)
		}
	}

	// One pin was recorded: a reload still matches the key and still rejects
	// a rotated one.
	kp2, err := LoadKnownPeers(path)
	if err != nil {
		t.Fatalf("reload: LoadKnownPeers() = %v", err)
	}
	if err := kp2.Pin(c); err != nil {
		t.Fatalf("after concurrent pins, same key: Pin() = %v", err)
	}
	rotated := c
	rotated.AttestKey = strings.Repeat("ff", 65)
	if err := kp2.Pin(rotated); err == nil {
		t.Fatal("after concurrent pins, Pin() = nil for a rotated key, want rejection")
	}
}

func TestLoadKnownPeersMissingFile(t *testing.T) {
	kp, err := LoadKnownPeers(filepath.Join(t.TempDir(), "does-not-exist.json"))
	if err != nil {
		t.Fatalf("LoadKnownPeers() = %v for a missing file, want empty store", err)
	}
	if err := kp.Pin(testPeerClaim("endpoint-dave", strings.Repeat("aa", 65))); err != nil {
		t.Fatalf("Pin() into fresh store = %v", err)
	}
}
