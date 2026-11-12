package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/tmc/go-iroh-experiments/irciroh"
	"github.com/tmc/go-iroh/key"
)

// testKey returns a distinct endpoint key for n, so that a test can
// name the keys it means without generating any.
func testKey(t *testing.T, n byte) key.EndpointID {
	t.Helper()
	var seed [32]byte
	for i := range seed {
		seed[i] = n
	}
	return key.NewSecretKey(seed).Public().EndpointID()
}

// writePeers writes the peers file under root as a person would, one
// "<key> <name> <first seen>" line for each pin.
func writePeers(t *testing.T, root string, pins map[key.EndpointID]string) {
	t.Helper()
	var b strings.Builder
	for id, name := range pins {
		fmt.Fprintf(&b, "%s %s 2026-09-19T08:19:14Z\n", id, name)
	}
	if err := os.WriteFile(filepath.Join(root, peersFile), []byte(b.String()), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestLoadPeers(t *testing.T) {
	alice := testKey(t, 1)
	tests := []struct {
		name string
		file string
		want string // the error, or "" for none
	}{
		{"absent", "", ""},
		{"comment and blank", "# a comment\n\n", ""},
		{"pin", alice.String() + " alice 2026-09-19T08:19:14Z\n", ""},
		{"short line", alice.String() + " alice\n", "fields"},
		{"bad key", "not-a-key alice 2026-09-19T08:19:14Z\n", "key"},
		{"bad time", alice.String() + " alice yesterday\n", "first seen"},
		{"bad name", alice.String() + " a\tlice 2026-09-19T08:19:14Z\n", "fields"},
	}
	for _, tt := range tests {
		root := t.TempDir()
		if tt.file != "" {
			if err := os.WriteFile(filepath.Join(root, peersFile), []byte(tt.file), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		_, err := loadPeers(root)
		switch {
		case tt.want == "" && err != nil:
			t.Errorf("%s: loadPeers = %v, want nil", tt.name, err)
		case tt.want != "" && err == nil:
			t.Errorf("%s: loadPeers = nil, want %q", tt.name, tt.want)
		case tt.want != "" && err != nil && !strings.Contains(err.Error(), tt.want):
			t.Errorf("%s: loadPeers = %v, want it to mention %q", tt.name, err, tt.want)
		}
	}
}

func TestOKName(t *testing.T) {
	tests := []struct {
		name string
		ok   bool
	}{
		{"alice", true},
		{"", false},
		{"two words", false},
		{"with#hash", false},
		{"nick[1]", true},
		{"a-b_c^d", true},
		{"\u0430lice", false}, // Cyrillic a, a picture of alice
		{"ali\u0441e", false}, // Cyrillic c, in the middle
		{"caf\u00e9", false},
		{"alice\U0001f600", false},
		{"al,ice", false},
		{"al:ice", false},
		{strings.Repeat("n", 32), true},
		{strings.Repeat("n", 33), false},
	}
	for _, tt := range tests {
		if err := okName(tt.name); (err == nil) != tt.ok {
			t.Errorf("okName(%q) = %v, want ok=%v", tt.name, err, tt.ok)
		}
	}
}

// A view holds one store and reloads it from a watcher while tool
// calls read it, so the two must not race.
func TestReloadRace(t *testing.T) {
	root := t.TempDir()
	alice := testKey(t, 1)
	writePeers(t, root, map[key.EndpointID]string{alice: "alice"})
	p, err := loadPeers(root)
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for range 4 {
		wg.Add(3)
		go func() { defer wg.Done(); p.reload() }()
		go func() { defer wg.Done(); p.name(alice) }()
		go func() { defer wg.Done(); p.holder("alice") }()
	}
	wg.Wait()
}

func TestVerdict(t *testing.T) {
	alice, mallory, dave := testKey(t, 1), testKey(t, 2), testKey(t, 3)
	root := t.TempDir()
	writePeers(t, root, map[key.EndpointID]string{
		alice: "alice",
		// A name the advertised casemapping folds, so that the store
		// and the clients reading it agree about how many names this is.
		dave: "tmc[1]",
	})
	p, err := loadPeers(root)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		id     key.EndpointID
		claims string
		want   verdict
		as     string
	}{
		{alice, "alice", pinnedAs, "alice"},
		{alice, "ALICE", pinnedAs, "alice"}, // the same name to every client
		{alice, "bob", renamed, "alice"},    // somebody we know, another name
		{mallory, "alice", claimed, ""},     // the attack
		{mallory, "carol", unknown, ""},     // a stranger, saying nothing we pinned

		// rfc1459 folds []\~ onto {}|^, so these are one name to every
		// client that read the 005 and have to be one name here. Told
		// apart, the second row would be a stranger with a free name
		// rather than the impersonation it is.
		{dave, "tmc{1}", pinnedAs, "tmc[1]"},
		{mallory, "tmc{1}", claimed, ""},
	}
	for _, tt := range tests {
		got, as := p.verdict(tt.id, tt.claims)
		if got != tt.want || as != tt.as {
			t.Errorf("verdict(%s, %q) = %v, %q; want %v, %q",
				short(tt.id), tt.claims, got, as, tt.want, tt.as)
		}
	}
}

// A verdict is a fact about the store now, not about when a line was
// written: pinning somebody settles every line they have ever said, as
// soon as the store reloads the file.
func TestVerdictFollowsThePin(t *testing.T) {
	root := t.TempDir()
	alice := testKey(t, 1)
	p, err := loadPeers(root)
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := p.verdict(alice, "alice"); got != unknown {
		t.Errorf("before pinning: verdict = %v, want %v", got, unknown)
	}
	writePeers(t, root, map[key.EndpointID]string{alice: "alice"})
	if err := p.reload(); err != nil {
		t.Fatal(err)
	}
	if got, _ := p.verdict(alice, "alice"); got != pinnedAs {
		t.Errorf("after pinning: verdict = %v, want %v", got, pinnedAs)
	}
}

// A line nobody signed has no claim to weigh. It is not a stranger.
func TestVerdictUnattributed(t *testing.T) {
	root := t.TempDir()
	writePeers(t, root, map[key.EndpointID]string{testKey(t, 1): "alice"})
	p, err := loadPeers(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"alice", "stranger", ""} {
		if got, as := p.verdict(key.EndpointID{}, name); got != unattributed || as != "" {
			t.Errorf("verdict(zero, %q) = %v, %q; want %v, \"\"", name, got, as, unattributed)
		}
	}
}

// The zero value is the safe end of the type: a verdict nobody set must
// never be the one that lets a view print a bare name.
func TestVerdictZeroValue(t *testing.T) {
	var v verdict
	if v == pinnedAs {
		t.Error("the zero verdict is pinnedAs; an unset field would render bare")
	}
	if v != unattributed {
		t.Errorf("the zero verdict is %v, want %v", v, unattributed)
	}
}

// The render rule ends at somebody's eye, so the one name that must
// never be pinnable is one that is a picture of a name already pinned.
func TestHomographIsNotPinnable(t *testing.T) {
	const (
		ascii    = "alice"
		homizing = "аlice" // Cyrillic a
	)
	if ascii == homizing {
		t.Fatal("the test fixtures are the same string")
	}
	alice, mallory := testKey(t, 1), testKey(t, 2)
	root := t.TempDir()
	// Not a collision: the two names do not fold together, which is the
	// whole problem. The file is refused for what the name is made of.
	writePeers(t, root, map[key.EndpointID]string{alice: ascii, mallory: homizing})
	if _, err := loadPeers(root); !errors.Is(err, errNotASCII) {
		t.Errorf("loadPeers with a homograph pinned = %v, want %v", err, errNotASCII)
	}
	writePeers(t, root, map[key.EndpointID]string{alice: ascii})
	p, err := loadPeers(root)
	if err != nil {
		t.Fatal(err)
	}
	// Unpinnable means always suffixed, which is the safe direction:
	// the reader is shown a key rather than a name they cannot check.
	if got, _ := p.verdict(mallory, homizing); got != unknown {
		t.Errorf("verdict(mallory, homograph) = %v, want %v", got, unknown)
	}
	if got, _ := p.verdict(alice, ascii); got != pinnedAs {
		t.Errorf("verdict(alice, %q) = %v, want %v", ascii, got, pinnedAs)
	}
}

// name returns the name pinned to id.
func (p *peers) name(id key.EndpointID) (string, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	pin, ok := p.byKey[id]
	return pin.Name, ok
}

// holder returns the key a name is pinned to.
func (p *peers) holder(name string) (key.EndpointID, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	id, ok := p.byName[irciroh.Fold(name)]
	return id, ok
}
