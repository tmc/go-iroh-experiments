//go:build !js

package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestBuildWASM(t *testing.T) {
	ctx := context.Background()
	wasm := filepath.Join(t.TempDir(), "wasm-gossip-chat.wasm")
	cmd := exec.CommandContext(ctx, "go", "build", "-o", wasm, ".")
	cmd.Env = append(os.Environ(), "GOOS=js", "GOARCH=wasm")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build wasm: %v\n%s", err, out)
	}
	if st, err := os.Stat(wasm); err != nil {
		t.Fatalf("stat wasm: %v", err)
	} else if st.Size() == 0 {
		t.Fatal("wasm binary is empty")
	}
}

func TestServeIndex(t *testing.T) {
	wasm := filepath.Join(t.TempDir(), "wasm-gossip-chat.wasm")
	if err := os.WriteFile(wasm, []byte("wasm"), 0o666); err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(newMux(wasm))
	defer ts.Close()

	// A bare "/" has no relay query, so the mux redirects to wire it in; the
	// default client follows the redirect and lands on the chat page.
	resp, err := http.Get(ts.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %s, want 200 OK", resp.Status)
	}
	if got := resp.Request.URL.Query().Get("relay"); got == "" {
		t.Fatalf("landing URL missing auto-wired relay query: %s", resp.Request.URL)
	}
	buf := make([]byte, 8192)
	n, _ := resp.Body.Read(buf)
	body := string(buf[:n])
	if !strings.Contains(body, "wasm-gossip-chat.wasm") {
		t.Fatalf("index missing wasm path: %q", body)
	}
}
