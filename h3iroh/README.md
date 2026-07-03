# h3iroh

`h3iroh` is an HTTP/3 connection adapter over an iroh connection: it lets an
HTTP/3 client and server speak over an iroh QUIC connection instead of a raw UDP
socket. It intentionally depends on go-iroh's public `http3` adapter rather than
importing go-iroh internals or bundling another QUIC stack.

It is a clean-room Go port of the Rust
[iroh-experiments](https://github.com/n0-computer/iroh-experiments) HTTP/3 work.

```sh
go get github.com/tmc/go-iroh-experiments/h3iroh
```

See the [package docs](https://pkg.go.dev/github.com/tmc/go-iroh-experiments/h3iroh)
for the API.
