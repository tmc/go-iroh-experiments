// Package h3iroh provides the go-iroh experiments HTTP/3 transport adapter.
//
// It adapts go-iroh's public connection and stream APIs without adding another
// QUIC stack. The adapter operates on an established iroh connection, so it
// cannot be demonstrated without binding endpoints and making a network
// connection; the package integration test provides a complete loopback
// example.
package h3iroh
