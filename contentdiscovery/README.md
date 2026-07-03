# contentdiscovery

`contentdiscovery` implements the iroh content tracker protocol: an overlay for
announcing which peers can serve a given blob or collection, and for finding
providers of content by its hash. It speaks ALPN `n0/tracker/1`.

The module includes:

- the tracker wire protocol (announce and query messages)
- an in-memory announcement store with expiry
- a tracker handler and client
- the [`content-tracker`](./cmd/content-tracker) server and
  [`content-discovery`](./cmd/content-discovery) client commands

It is a clean-room Go port of the Rust
[iroh-experiments](https://github.com/n0-computer/iroh-experiments) content
tracker, targeting wire compatibility.

```sh
go get github.com/tmc/go-iroh-experiments/contentdiscovery
```

See the [package docs](https://pkg.go.dev/github.com/tmc/go-iroh-experiments/contentdiscovery)
for the API.
