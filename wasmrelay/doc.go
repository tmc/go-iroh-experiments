// Package wasmrelay contains a browser relay-only demo for go-iroh.
//
// The demo command builds a small js/wasm endpoint, starts a local relay HTTP
// server, and serves a page that runs two browser iroh endpoints over that
// relay with IP transports disabled.
package wasmrelay
