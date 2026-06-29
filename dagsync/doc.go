// Package dagsync implements the iroh-dag-sync example protocol.
//
// The wire protocol uses ALPN DAG_SYNC/1. A client writes one postcard Request
// to a bidirectional stream. The response is a sequence of 33-byte postcard
// SyncResponseHeader values, each optionally followed by a full-range BAO blob.
package dagsync
