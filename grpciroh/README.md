# grpciroh

`grpciroh` runs unmodified gRPC services over an iroh QUIC connection. It speaks
ALPN `grpc/iroh/1`.

The server side needs no adapter code: bind an iroh endpoint with the ALPN, call
`Endpoint.ListenStreams`, and hand the listener to `grpc.Server.Serve`. The
client side supplies the iroh stream dialer and credentials:

```go
conn, err := ep.Connect(ctx, addr, grpciroh.ALPN)
cc, err := grpc.NewClient(peerID.String(), grpciroh.DialOptions(conn)...)
```

`DialOptions` uses gRPC insecure credentials because gRPC adds no TLS of its own.
The transport is still authenticated and encrypted: iroh authenticates peers by
Ed25519 EndpointID and encrypts streams at the QUIC layer.

See the [`grpc-iroh-demo`](./cmd/grpc-iroh-demo) command for a runnable client
that connects by EndpointID, and the
[package docs](https://pkg.go.dev/github.com/tmc/go-iroh-experiments/grpciroh)
for the API.

```sh
go get github.com/tmc/go-iroh-experiments/grpciroh
```
