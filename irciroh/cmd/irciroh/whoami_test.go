package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// TestMCPWhoami checks that a view can answer who it speaks as, from
// the directory alone.
//
// The identity belongs to the directory rather than to the session
// holding a view of it, so the answer is the nick and the whole key
// written there by the chat. The whole key matters: keyTMC and
// keyNotTMC agree in the six hex digits a hostmask shows, so a tool
// that answered with the short form would let one agent mistake the
// other for itself - which is the confusion this tool exists to end.
//
// Negative control: a directory no chat has attached to has no
// identity to report, and says so rather than answering with an empty
// nick that reads like a real one.
func TestMCPWhoami(t *testing.T) {
	root := chatDir(t, "2026-01-01T00:00:00Z -!- alice joined #go")
	if err := os.WriteFile(filepath.Join(root, "nick"), []byte("tmc\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "key"), []byte(keyTMC+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cs := session(t, root)
	got := call[whoamiOut](t, cs, "irc_whoami", whoamiIn{})
	if got.Nick != "tmc" {
		t.Errorf("nick = %q, want tmc", got.Nick)
	}
	if got.Key != keyTMC {
		t.Errorf("key = %q, want the whole key %q", got.Key, keyTMC)
	}
	if got.Key == keyNotTMC || strings.HasPrefix(got.Key, shortKey(keyNotTMC)) && got.Key != keyTMC {
		t.Errorf("key = %q, which a grinder could have reached", got.Key)
	}
	if got.Dir != root {
		t.Errorf("dir = %q, want %q", got.Dir, root)
	}

	bare := t.TempDir()
	none := call[whoamiOut](t, session(t, bare), "irc_whoami", whoamiIn{})
	if none.Nick != "" || none.Key != "" {
		t.Errorf("whoami(%s) = %+v, want no identity", bare, none)
	}
	if none.Dir != bare {
		t.Errorf("dir = %q, want %q", none.Dir, bare)
	}
}

// TestMCPWhoamiSaysWhatItCounted checks that the answer never implies
// a roster of views.
//
// A chat takes an exclusive lock on the directory, so whether one is
// attached is knowable; a view takes nothing, so how many views there
// are is not. Reporting a count would be inventing one, and an agent
// comparing an invented count is worse off than an agent told plainly
// that its lines are not distinguishable. So the prose says that other
// views share the identity, and names no number.
//
// Both views are asked, because two views of one directory is the case
// that made the tool necessary and neither may be told it is alone.
func TestMCPWhoamiSaysWhatItCounted(t *testing.T) {
	root := chatDir(t, "2026-01-01T00:00:00Z -!- alice joined #go")
	if err := os.WriteFile(filepath.Join(root, "nick"), []byte("tmc\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "key"), []byte(keyTMC+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for i, cs := range []*mcp.ClientSession{session(t, root), session(t, root)} {
		res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: "irc_whoami"})
		if err != nil {
			t.Fatal(err)
		}
		said := text2(res)
		if !strings.Contains(said, "belongs to the directory") {
			t.Errorf("view %d does not say the identity belongs to the directory: %s", i, said)
		}
		if !strings.Contains(said, "not marked apart from yours") {
			t.Errorf("view %d does not say its lines are indistinguishable: %s", i, said)
		}
		for _, n := range []string{"1 ", "2 ", "one ", "two "} {
			if strings.Contains(said, n+"view") || strings.Contains(said, n+"client") {
				t.Errorf("view %d reports a count it cannot know: %s", i, said)
			}
		}
	}
}
