// Package wasmrelay contains browser relay-only demos for go-iroh.
//
// The wasmrelay-demo command builds a small js/wasm endpoint, starts a local
// relay HTTP server, and serves a page that runs two browser iroh endpoints
// over that relay with IP transports disabled.
//
// The wasm-gossip-chat command extends that to a cross-tab gossip chat: each
// browser tab is one relay-only endpoint that joins a shared gossip topic, and
// tabs exchange live messages with a self-healing overlay.
package wasmrelay
