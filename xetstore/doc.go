// Package xetstore stores BAO outboards for HuggingFace files served by the
// Xet content-addressed store.
//
// Importing a file reads it once through the HuggingFace resolve URL to compute
// its BLAKE3 root and BAO outboard. The data itself stays remote when the Hub
// supports HTTP range requests; later reads use range requests against the Xet
// backend. Use WithToken for gated or private repositories.
//
// NOTE: This package uses the Hub resolve endpoint. Native Xet CAS
// reconstruction would fetch /v1/reconstructions metadata, then assemble file
// bytes from term ranges and fetch_info xorb URLs. That dedup-aware path is a
// future data source, not part of this package's current implementation.
package xetstore
