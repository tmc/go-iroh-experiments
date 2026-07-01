//go:build !js

package main

import (
	"context"
	"flag"
	"fmt"
	"html"
	"log"
	"net"
	"net/http"
	"net/url"
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
	tmp, err := os.MkdirTemp("", "wasmrelay-demo-*")
	if err != nil {
		return fmt.Errorf("make temp dir: %w", err)
	}
	defer os.RemoveAll(tmp)

	wasm := filepath.Join(tmp, "wasmrelay-demo.wasm")
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

	mux := newMux(wasm)
	url := "http://" + ln.Addr().String() + "/"
	fmt.Printf("serving wasmrelay demo at %s\n", url)
	fmt.Println("open the URL in a browser; the page reports pass after the relay-only echo")
	return http.Serve(ln, mux)
}

func newMux(wasm string) http.Handler {
	wasmExec := filepath.Join(runtimeRoot(), "lib", "wasm", "wasm_exec.js")
	mux := http.NewServeMux()
	mux.Handle("/relay", relayserver.New())
	mux.HandleFunc("/wasm_exec.js", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, wasmExec)
	})
	mux.HandleFunc("/wasmrelay-demo.wasm", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/wasm")
		http.ServeFile(w, r, wasm)
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		relay := "http://" + r.Host + "/"
		fmt.Fprintf(w, `<!doctype html>
<html><head><meta charset="utf-8"><script src="/wasm_exec.js"></script></head>
<body data-status="running" data-detail="starting">
<script>
const go = new Go();
WebAssembly.instantiateStreaming(fetch("/wasmrelay-demo.wasm"), go.importObject)
  .then((result) => go.run(result.instance))
  .catch((err) => {
    document.body.textContent = String(err);
    document.body.setAttribute("data-status", "fail");
    document.body.setAttribute("data-detail", String(err));
  });
</script>
<a id="relay" href="?relay=%s"></a>
<script>
if (!location.search) location.replace(document.getElementById("relay").href);
</script>
</body></html>`, html.EscapeString(url.QueryEscape(relay)))
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
