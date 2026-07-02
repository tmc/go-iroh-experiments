//go:build !js

// Command wasm-gossip-chat serves a go-iroh browser (js/wasm) gossip chat demo:
// open the page in several tabs and they chat across tabs over a relay, with no
// direct IP connectivity. It builds the js/wasm node, serves it alongside a
// hermetic relay and an interactive page, and auto-wires the relay URL.
//
// Open the printed URL in one tab (the "host"), then open the invite URL that
// page shows — it carries ?peer=<host-id> — in more tabs to fill the room.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/tmc/go-iroh/relayserver"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:0", "HTTP listen address")
	flag.Parse()

	if err := run(context.Background(), *addr); err != nil {
		log.Fatal(err)
	}
}

func run(ctx context.Context, addr string) error {
	tmp, err := os.MkdirTemp("", "wasm-gossip-chat-*")
	if err != nil {
		return fmt.Errorf("make temp dir: %w", err)
	}
	defer os.RemoveAll(tmp)

	wasm := filepath.Join(tmp, "wasm-gossip-chat.wasm")
	build := exec.CommandContext(ctx, "go", "build", "-o", wasm, ".")
	build.Env = append(os.Environ(), "GOOS=js", "GOARCH=wasm")
	if out, err := build.CombinedOutput(); err != nil {
		return fmt.Errorf("build wasm: %w\n%s", err, out)
	}

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	defer ln.Close()

	url := "http://" + ln.Addr().String() + "/"
	fmt.Printf("serving wasm gossip chat demo at %s\n", url)
	fmt.Println("open it in one tab, then open the invite URL it shows in more tabs")
	return http.Serve(ln, newMux(wasm))
}

func newMux(wasm string) http.Handler {
	wasmExec := filepath.Join(runtimeRoot(), "lib", "wasm", "wasm_exec.js")
	mux := http.NewServeMux()
	mux.Handle("/relay", relayserver.New())
	mux.HandleFunc("/wasm_exec.js", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, wasmExec)
	})
	mux.HandleFunc("/wasm-gossip-chat.wasm", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/wasm")
		http.ServeFile(w, r, wasm)
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// Auto-wire the relay to this server if absent, so a bare visit to "/"
		// just works. The wasm dials <relay>/relay.
		q := r.URL.Query()
		if q.Get("relay") == "" {
			q.Set("relay", "http://"+r.Host+"/")
			http.Redirect(w, r, r.URL.Path+"?"+q.Encode(), http.StatusFound)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, page)
	})
	return mux
}

func runtimeRoot() string {
	if goroot := os.Getenv("GOROOT"); goroot != "" {
		return goroot
	}
	out, err := exec.Command("go", "env", "GOROOT").Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}
