# go-iroh-experiments expansion

Internal planning note: where the experiment collection should grow next,
and what should graduate out of it.

## Design invariants

- One module per experiment; dependencies stay isolated, each module can be
  released or abandoned independently.
- Ports of Rust iroh-experiments target wire compatibility and say so;
  original experiments say what question they explore.
- An experiment that stops being experimental should graduate (to go-iroh,
  go-iroh-tools, or its own repo), not accrete here.

## Current state (2026-08)

Thirteen modules: five ports of Rust iroh-experiments (`pkarrnaming`,
`contentdiscovery`, `s3baostore`, `dagsync`, `h3iroh`) and eight originals
(`dtrain`, `directpath`, `grpciroh`, `tlogiroh`, `wasmrelay`, `enclaveiroh`,
`x402iroh`, `xetstore`). All build against current go-iroh main.

Known issue: `x402iroh` has a failing test (`TestUnpaidRequestChallenged`,
500 instead of 402) that predates the 2026-08 dependency refresh. Fix or
mark the module stale before adding anything near it.

## Candidate additions

### Remaining Rust iroh-experiments ports

Check the upstream tree for subprojects not yet ported before starting
anything original; ports have a built-in success criterion (wire compat with
the Rust side) that originals lack. As of the last survey the low-hanging
ports were done; re-survey upstream when planning the next batch.

### frostiroh — threshold identity

FROST threshold signatures over an endpoint key: k-of-n signers jointly
control one iroh identity. Explores whether `key`'s signing surface can host
a remote/threshold signer without API changes. Natural follow-on to
`enclaveiroh`'s attestation work.

### relaymesh — relay-to-relay federation

Multiple `relayserver` instances forwarding for each other, so a client
homed on relay A can reach a client homed on relay B without either
switching homes. Tests how far the embeddable relay server stretches beyond
the single-server deployment go-iroh assumes.

### mcpiroh — MCP transport over iroh

Model Context Protocol framing over an iroh stream, so agents reach tools
by endpoint ID with mutual key authentication instead of localhost pipes or
bearer-token HTTP. Small (framing plus an ALPN), timely, and a good
demonstration of `irpc`-adjacent patterns.

## Graduation watch

- `h3iroh` duplicates ground now covered by go-iroh's `http3` package;
  decide whether it still earns its place or should shrink to a
  compatibility shim over the upstream package.
- `directpath` is a validation harness more than an experiment; if it
  stabilizes further it belongs beside the perf/validation repos, not here.
- `dtrain` has a much larger sibling (the mlx-ccl stack); keep dtrain as
  the small didactic version and resist growing it.

## Infrastructure debt

- No go.work-wide CI gate: a single `go build ./... && go test ./...` per
  module, run across all modules, would have caught the x402iroh breakage
  earlier. Add a script or Makefile target that iterates the modules.
