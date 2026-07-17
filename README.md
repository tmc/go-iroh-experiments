# go-iroh-experiments

Experimental modules built on [github.com/tmc/go-iroh](https://github.com/tmc/go-iroh).
Each experiment is its own Go module so its dependencies stay isolated and it
can be released independently.

Several modules are clean-room Go ports of the corresponding Rust
[iroh-experiments](https://github.com/n0-computer/iroh-experiments) subprojects,
targeting wire compatibility. Others are original experiments that explore what
go-iroh enables.

## Ports of Rust iroh-experiments

| Module | Purpose |
|---|---|
| `pkarrnaming` | content naming published and resolved over the pkarr relay transport |
| `contentdiscovery` | tracker overlay for announcing and finding content providers (ALPN `n0/tracker/1`) |
| `s3baostore` | iroh-blobs provider backed by a remote S3/HTTP object store |
| `dagsync` | IPLD DAG synchronization over iroh (ALPN `DAG_SYNC/1`) |
| `h3iroh` | HTTP/3 connection adapter over an iroh connection |

## Original experiments

| Module | Purpose |
|---|---|
| `dtrain` | distributed-training collectives (AllReduce, broadcast, barrier) over a gossip group (ALPN `/dtrain/1`) |
| `directpath` | direct-only QUIC path probe for cross-host and dual-stack go-iroh validation |
| `grpciroh` | run unmodified gRPC services over an iroh QUIC connection (ALPN `grpc/iroh/1`) |
| `tlogiroh` | distributed transparency log: sumdb/tlog tiles as iroh blobs, gossiped note-signed checkpoints, witness K-of-N cosigning |
| `wasmrelay` | browser (js/wasm) relay-only demos, including a cross-tab gossip chat |
| `x402iroh` | x402-paid HTTP over iroh: endpoint keys authorize payments on an `iroh:ed25519` network (ALPN `x402/iroh/1`) |
| `xetstore` | serve HuggingFace/Xet files as iroh blobs via BAO outboards over HTTP range requests |

Each module has its own `README.md` and package docs.

## Use

Each module is independent. To use one:

```sh
go get github.com/tmc/go-iroh-experiments/pkarrnaming
```

All modules declare Go 1.26.

## Development

A `go.work` file ties the modules together for local development against a
checkout of `go-iroh`. It is intentionally not committed, since it carries a
local `replace` directive. Create it locally with:

```sh
go work init ./contentdiscovery ./dagsync ./dtrain ./grpciroh ./h3iroh \
    ./directpath ./pkarrnaming ./s3baostore ./tlogiroh ./wasmrelay \
    ./x402iroh ./xetstore
go work edit -replace github.com/tmc/go-iroh=../go-iroh   # optional, for local go-iroh work
go work edit -replace github.com/tmc/x402=../x402         # optional, for local x402 work
```

Run a module's tests from inside its directory:

```sh
cd pkarrnaming && go test ./...
```

## License

go-iroh-experiments is licensed under the MIT License. See [LICENSE](./LICENSE).
