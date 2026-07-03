# dagsync

`dagsync` implements the iroh-dag-sync example protocol: synchronizing IPLD DAGs
between peers over iroh. It speaks ALPN `DAG_SYNC/1`.

A client writes one postcard `Request` to a bidirectional stream. The response is
a sequence of 33-byte postcard `SyncResponseHeader` values, each optionally
followed by a full-range BAO blob, letting the client verify and store the DAG
incrementally.

It is a clean-room Go port of the Rust
[iroh-experiments](https://github.com/n0-computer/iroh-experiments) dag-sync
example, targeting wire compatibility.

```sh
go get github.com/tmc/go-iroh-experiments/dagsync
```

See the [package docs](https://pkg.go.dev/github.com/tmc/go-iroh-experiments/dagsync)
for the API.
