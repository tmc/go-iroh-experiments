package irciroh

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tmc/go-iroh/key"
)

func testID(t *testing.T) key.EndpointID {
	t.Helper()
	sk, err := key.GenerateSecretKey()
	if err != nil {
		t.Fatal(err)
	}
	return sk.Public().EndpointID()
}

func TestStateBansRoundTrip(t *testing.T) {
	dir := t.TempDir()
	b, err := openState(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got := b.bans("#vault"); len(got) != 0 {
		t.Fatalf("fresh store lists %d bans, want 0", len(got))
	}

	one, two := testID(t), testID(t)
	if err := b.ban("#Vault", one); err != nil {
		t.Fatal(err)
	}
	if err := b.ban("#vault", two); err != nil {
		t.Fatal(err)
	}
	if err := b.ban("#other", one); err != nil {
		t.Fatal(err)
	}
	// A repeat is not an error and does not grow the file.
	if err := b.ban("#vault", one); err != nil {
		t.Fatal(err)
	}

	again, err := openState(dir)
	if err != nil {
		t.Fatal(err)
	}
	got := again.bans("#VAULT")
	if len(got) != 2 {
		t.Fatalf("reopened store lists %v, want both bans on #vault", got)
	}
	if len(again.bans("#other")) != 1 {
		t.Fatalf("#other lost its ban: %v", again.bans("#other"))
	}

	body, err := os.ReadFile(filepath.Join(dir, "bans"))
	if err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(strings.TrimSpace(string(body)), "\n") + 1; n != 3 {
		t.Fatalf("ban file has %d lines, want 3:\n%s", n, body)
	}
	t.Logf("ban file:\n%s", body)
}

func TestStateSecretsRoundTrip(t *testing.T) {
	dir := t.TempDir()
	s, err := openState(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got := s.secret("#vault"); got != nil {
		t.Fatalf("fresh state has a secret: %x", got)
	}
	if err := s.setSecret("#Vault", []byte("a-secret-32-bytes-long-enough-ok")); err != nil {
		t.Fatal(err)
	}
	again, err := openState(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(again.secret("#VAULT")); got != "a-secret-32-bytes-long-enough-ok" {
		t.Fatalf("reopened secret is %q", got)
	}
	fi, err := os.Stat(filepath.Join(dir, "secrets"))
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("secrets file is %v, want 0600: it is a credential", fi.Mode().Perm())
	}
}

// TestStateRejectsJunk checks that a state file that is malformed,
// truncated, or names no channel stops the node rather than being
// half-read. The files are replaced by rename, so a torn one comes from
// a disk or a hand edit, and a guessed ban list or a shortened secret
// is worse than refusing to start.
func TestStateRejectsJunk(t *testing.T) {
	id := testID(t).String()
	secret := strings.Repeat("ab", 32)
	tests := []struct {
		name, file, body string
	}{
		{"ban names no endpoint", "bans", "#vault not-an-endpoint\n"},
		{"ban truncated", "bans", "#vault " + id[:len(id)-2] + "\n"},
		{"ban with no value", "bans", "#vault\n"},
		{"ban on no channel", "bans", "vault " + id + "\n"},
		{"secret not hex", "secrets", "#vault zz\n"},
		{"secret truncated", "secrets", "#vault " + secret[:8] + "\n"},
		{"secret too long", "secrets", "#vault " + secret + "ab\n"},
		{"secret on no channel", "secrets", "vault " + secret + "\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, tt.file), []byte(tt.body), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := openState(dir); err == nil {
				t.Fatalf("%s %q was accepted", tt.file, tt.body)
			}
		})
	}
	dir := t.TempDir()
	for file, body := range map[string]string{"bans": "#Vault " + id, "secrets": "#Vault " + secret} {
		if err := os.WriteFile(filepath.Join(dir, file), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	s, err := openState(dir)
	if err != nil {
		t.Fatalf("control: a well-formed state with no final newline: %v", err)
	}
	if len(s.bans("#vault")) != 1 || len(s.secret("#vault")) != 32 {
		t.Fatalf("control: read %v and %x", s.bans("#vault"), s.secret("#vault"))
	}
}

// TestBanStoreNil checks that a node without a state directory works and
// simply forgets: the store is nil and every method tolerates it.
func TestStateNil(t *testing.T) {
	var b *state
	if got := b.bans("#vault"); got != nil {
		t.Fatalf("nil state listed %v", got)
	}
	if err := b.ban("#vault", testID(t)); err != nil {
		t.Fatalf("nil state ban: %v", err)
	}
	if got := b.secret("#vault"); got != nil {
		t.Fatalf("nil state has a secret: %x", got)
	}
	if err := b.setSecret("#vault", []byte("s")); err != nil {
		t.Fatalf("nil state setSecret: %v", err)
	}
}

// TestStateFailedWriteChangesNothing checks that a change that could not
// be written is not held in memory either. A ban kept only in memory
// made the retry a no-op that reported success with nothing on disk.
func TestStateFailedWriteChangesNothing(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root writes to a read-only directory")
	}
	dir := t.TempDir()
	s, err := openState(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(dir, 0o700) })

	id := testID(t)
	if err := s.ban("#vault", id); err == nil {
		t.Fatal("ban into a read-only directory reported success")
	}
	if got := s.bans("#vault"); len(got) != 0 {
		t.Fatalf("failed ban is held in memory: %v", got)
	}
	if err := s.setSecret("#vault", []byte("a-secret-32-bytes-long-enough-ok")); err == nil {
		t.Fatal("setSecret into a read-only directory reported success")
	}
	if got := s.secret("#vault"); got != nil {
		t.Fatalf("failed secret is held in memory: %x", got)
	}

	// Once the directory is writable the same calls write.
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := s.ban("#vault", id); err != nil {
		t.Fatal(err)
	}
	if err := s.setSecret("#vault", []byte("a-secret-32-bytes-long-enough-ok")); err != nil {
		t.Fatal(err)
	}
	again, err := openState(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got := again.bans("#vault"); len(got) != 1 || got[0] != id {
		t.Fatalf("retried ban reads back as %v", got)
	}
	if got := string(again.secret("#vault")); got != "a-secret-32-bytes-long-enough-ok" {
		t.Fatalf("retried secret reads back as %q", got)
	}
}
