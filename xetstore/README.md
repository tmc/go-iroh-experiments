# xetstore

`xetstore` stores BAO outboards for HuggingFace files served by the
[Xet](https://huggingface.co/blog/xet-on-the-hub) content-addressed store, so a
model or dataset file can be served as an iroh blob without copying it locally.

Importing a file reads it once through the HuggingFace resolve URL to compute its
BLAKE3 root and BAO outboard. The data stays remote when the Hub supports HTTP
range requests; later reads use range requests against the Xet backend. Use
`WithToken` for gated or private repositories.

> Note: this package uses the Hub resolve endpoint. Native Xet CAS
> reconstruction (assembling file bytes from term ranges and `fetch_info` xorb
> URLs) is a future data source, not part of the current implementation.

```sh
go get github.com/tmc/go-iroh-experiments/xetstore
```

See `ExampleStore_servingBlob` and the
[package docs](https://pkg.go.dev/github.com/tmc/go-iroh-experiments/xetstore)
for the API.
