# wasmrelay

`wasmrelay` contains browser (js/wasm) relay-only demos for go-iroh: iroh
endpoints running inside a browser tab, connected over a relay with IP transports
compiled out.

Two commands:

- [`wasmrelay-demo`](./cmd/wasmrelay-demo) builds a small js/wasm endpoint,
  starts a local relay HTTP server, and serves a page that runs two browser iroh
  endpoints over that relay.
- [`wasm-gossip-chat`](./cmd/wasm-gossip-chat) extends that to a cross-tab gossip
  chat: each browser tab is one relay-only endpoint that joins a shared gossip
  topic, and tabs exchange live messages over a self-healing overlay.

Each command's native side builds the wasm, serves it alongside a hermetic relay,
and opens in the browser. Run one with:

```sh
go run ./cmd/wasm-gossip-chat
```

then open the printed URL in several tabs.

See the [package docs](https://pkg.go.dev/github.com/tmc/go-iroh-experiments/wasmrelay)
for details.
