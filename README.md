# go-iroh-experiments

Experimental modules built on [github.com/tmc/go-iroh](https://github.com/tmc/go-iroh).
Each experiment is its own Go module so its dependencies stay isolated and it
can be released independently. They are clean-room Go ports of the corresponding
Rust [iroh-experiments](https://github.com/n0-computer/iroh-experiments)
subprojects, targeting wire compatibility.

## Modules

| Module | Purpose |
|---|---|
| `pkarrnaming` | IPNS-style content naming published over the pkarr relay transport |
| `contentdiscovery` | tracker overlay for announcing and finding content providers (ALPN `n0/tracker/1`) |
| `s3baostore` | iroh-blobs provider backed by a remote S3/HTTP object store |
| `dagsync` | IPLD DAG synchronization over iroh (ALPN `DAG_SYNC/1`) |
| `h3iroh` | HTTP/3 connection adapter over an iroh connection |

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
go work init ./contentdiscovery ./dagsync ./h3iroh ./pkarrnaming ./s3baostore
go work edit -replace github.com/tmc/go-iroh=../go-iroh   # optional, for local go-iroh work
```

Run a module's tests from inside its directory:

```sh
cd pkarrnaming && go test ./...
```

## License

go-iroh-experiments is licensed under the MIT License. See [LICENSE](./LICENSE).
