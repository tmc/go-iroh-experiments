package enclaveiroh

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// A KnownPeers store pins attestation keys by trust-on-first-use: the first
// verified claim from an endpoint records that endpoint's attestation key,
// and every later claim from the same endpoint must present the same key.
// TOFU defends against a recorded key changing — key rotation, or a stolen
// endpoint key resurfacing with a new attestation key — not against
// impersonation on first contact, when there is nothing to compare against.
//
// The store is a JSON file of endpoint → {attest_key, cdhash, first_seen}.
// It holds only claim fields and standard-library types, so it works on any
// platform. [KnownPeers.Pin] matches [Policy.PinPeer]; it is safe for
// concurrent use by the per-connection handshakes of a server.
type KnownPeers struct {
	path string

	mu    sync.Mutex
	peers map[string]knownPeer
}

// knownPeer is one first-contact record. CDHash is what the endpoint's code
// was at first contact — recorded for audit, not enforced, since a rebuild
// legitimately changes it while the attestation key persists.
type knownPeer struct {
	AttestKey string `json:"attest_key"` // X9.63 hex, as claimed
	CDHash    string `json:"cdhash,omitempty"`
	FirstSeen string `json:"first_seen"` // RFC3339, verifier-local clock
}

// LoadKnownPeers opens the store at path, creating an empty one if the file
// does not exist yet.
func LoadKnownPeers(path string) (*KnownPeers, error) {
	s := &KnownPeers{path: path, peers: make(map[string]knownPeer)}
	b, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return nil, fmt.Errorf("known peers: %w", err)
	}
	if err := json.Unmarshal(b, &s.peers); err != nil {
		return nil, fmt.Errorf("known peers %s: %w", path, err)
	}
	return s, nil
}

// Pin implements trust-on-first-use over a verified claim: the first claim
// from an endpoint records its attestation key (persisting the store
// immediately), and a later claim whose key differs is rejected. The
// endpoint identity is the claim's local_endpoint, which [VerifyClaim] has
// already bound to the connection's authenticated peer.
func (s *KnownPeers) Pin(c Claim) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	known, ok := s.peers[c.LocalEndpoint]
	if !ok {
		s.peers[c.LocalEndpoint] = knownPeer{
			AttestKey: c.AttestKey,
			CDHash:    c.CDHash,
			FirstSeen: time.Now().UTC().Format(time.RFC3339),
		}
		return s.save()
	}
	if known.AttestKey != c.AttestKey {
		return fmt.Errorf("known peers: endpoint %s attestation key changed since first contact %s",
			c.LocalEndpoint, known.FirstSeen)
	}
	return nil
}

// save writes the store atomically (temp file + fsync + rename), so a crash
// mid-write cannot truncate the pins already recorded.
func (s *KnownPeers) save() error {
	b, err := json.MarshalIndent(s.peers, "", "\t")
	if err != nil {
		return fmt.Errorf("known peers: %w", err)
	}
	tmp, err := os.CreateTemp(filepath.Dir(s.path), ".knownpeers-*")
	if err != nil {
		return fmt.Errorf("known peers: %w", err)
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(append(b, '\n')); err != nil {
		tmp.Close()
		return fmt.Errorf("known peers: %w", err)
	}
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return fmt.Errorf("known peers: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("known peers: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("known peers: %w", err)
	}
	if err := os.Rename(tmp.Name(), s.path); err != nil {
		return fmt.Errorf("known peers: %w", err)
	}
	return nil
}
