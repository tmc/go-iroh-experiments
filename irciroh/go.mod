module github.com/tmc/go-iroh-experiments/irciroh

go 1.27

require (
	github.com/modelcontextprotocol/go-sdk v1.8.0
	github.com/tmc/go-iroh v0.3.0
	github.com/tmc/go-iroh-experiments/mlsiroh v0.0.0-00010101000000-000000000000
	github.com/tmc/mls v0.0.0-00010101000000-000000000000
	lukechampine.com/blake3 v1.4.1
)

require (
	filippo.io/edwards25519 v1.2.0 // indirect
	github.com/coder/websocket v1.8.14 // indirect
	github.com/google/jsonschema-go v0.4.3 // indirect
	github.com/klauspost/cpuid/v2 v2.0.9 // indirect
	github.com/quic-go/quic-go v0.62.0 // indirect
	github.com/segmentio/asm v1.1.3 // indirect
	github.com/segmentio/encoding v0.5.4 // indirect
	github.com/yosida95/uritemplate/v3 v3.0.2 // indirect
	golang.org/x/crypto v0.57.0 // indirect
	golang.org/x/net v0.58.0 // indirect
	golang.org/x/oauth2 v0.35.0 // indirect
	golang.org/x/sync v0.22.0 // indirect
	golang.org/x/sys v0.48.0 // indirect
	golang.org/x/time v0.15.0 // indirect
)

// The sibling mlsiroh module has no published version, and both modules
// use github.com/tmc/mls API that is not yet in one. Until they are
// published, build against this repository and a sibling checkout of
// github.com/tmc/mls.
replace github.com/tmc/go-iroh-experiments/mlsiroh => ../mlsiroh

replace github.com/tmc/mls => ../../mls
