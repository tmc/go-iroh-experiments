# pkarrnaming

`pkarrnaming` publishes and resolves iroh content names using
[pkarr](https://github.com/pubky/pkarr): sovereign, public-key–addressed DNS
records distributed over Mainline DHT relays. A content record maps a name to an
iroh blob or collection so peers can resolve it without a central registry.

The module includes:

- a content record type carried in a pkarr signed packet
- a pluggable naming client for publishing and resolving records
- a pkarr relay transport for reaching the record store over HTTP

It is a clean-room Go port of the Rust
[iroh-experiments](https://github.com/n0-computer/iroh-experiments) pkarr naming
work, targeting wire compatibility.

```sh
go get github.com/tmc/go-iroh-experiments/pkarrnaming
```

See the [`pkarr-naming`](./cmd/pkarr-naming) command for a runnable CLI, and the
[package docs](https://pkg.go.dev/github.com/tmc/go-iroh-experiments/pkarrnaming)
for the API.
