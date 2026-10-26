# arpciroh

`arpciroh` runs unmodified [aRPC services](https://github.com/pancsta/asyncmachine-go/tree/main/pkg/rpc) over an iroh QUIC connection for secure state machine synchronization. It speaks
ALPN `arpc/1`.

The `github.com/pancsta/asyncmachine-go/pkg/rpc/iroh` package provides dedicated constructors for iroh-wrapped aRPC components (Client, Server, Mux).

```go
s, err := amiroh.NewServer(ctx, "127.0.0.1:0", id, netSrc, sOpts)
s.Start(nil)
```
