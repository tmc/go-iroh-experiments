package grpciroh

import (
	"context"
	"net"

	"github.com/tmc/go-iroh/iroh"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/resolver"
)

// ALPN is the iroh ALPN that routes gRPC-over-iroh connections.
const ALPN = "grpc/iroh/1"

// NewDialer returns a dial function for grpc.WithContextDialer that opens one
// bidirectional iroh stream per gRPC channel. gRPC layers HTTP/2 over that
// single stream and multiplexes every RPC call as an HTTP/2 stream within it;
// it does not open a new iroh stream per call.
//
// The address argument supplied by gRPC is ignored: conn is already connected
// to a known peer. The caller owns conn's lifecycle.
func NewDialer(conn *iroh.Conn) func(ctx context.Context, addr string) (net.Conn, error) {
	return func(ctx context.Context, _ string) (net.Conn, error) {
		return conn.OpenStreamConn(ctx)
	}
}

// DialOptions returns the grpc.DialOption values needed to run gRPC over conn:
// the iroh stream dialer, insecure transport credentials, and a local resolver
// that passes the EndpointID target through to the dialer.
//
// The credentials are "insecure" only in the sense that gRPC adds no TLS of its
// own. The transport is not insecure: iroh authenticates both peers by Ed25519
// EndpointID and encrypts every stream at the QUIC layer.
func DialOptions(conn *iroh.Conn) []grpc.DialOption {
	return []grpc.DialOption{
		grpc.WithContextDialer(NewDialer(conn)),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithResolvers(endpointIDResolver{}),
	}
}

// Conn wraps a *grpc.ClientConn that owns the underlying *iroh.Conn. Closing it
// closes both. Use NewClient when the adapter, not the caller, created the
// iroh.Conn; when the caller owns the iroh.Conn, use DialOptions with
// grpc.NewClient directly and close each independently.
type Conn struct {
	*grpc.ClientConn
	iroh *iroh.Conn
}

// NewClient returns a gRPC client connection that runs over conn and takes
// ownership of conn: Close closes the gRPC connection and then conn.
//
// Target sets the HTTP/2 :authority pseudo-header. Pass
// conn.RemoteID().String() for authority keyed on the peer's identity. Extra
// options are appended after the iroh dialer and credentials.
func NewClient(conn *iroh.Conn, target string, extra ...grpc.DialOption) (*Conn, error) {
	cc, err := grpc.NewClient(target, append(DialOptions(conn), extra...)...)
	if err != nil {
		return nil, err
	}
	return &Conn{ClientConn: cc, iroh: conn}, nil
}

// Close closes the gRPC client connection and the underlying iroh connection.
func (c *Conn) Close() error {
	err := c.ClientConn.Close()
	if cerr := c.iroh.Close(); err == nil {
		err = cerr
	}
	return err
}

type endpointIDResolver struct{}

func (endpointIDResolver) Build(target resolver.Target, cc resolver.ClientConn, opts resolver.BuildOptions) (resolver.Resolver, error) {
	r := endpointIDResolution{target: target, cc: cc}
	r.ResolveNow(resolver.ResolveNowOptions{})
	return r, nil
}

func (endpointIDResolver) Scheme() string {
	return "dns"
}

type endpointIDResolution struct {
	target resolver.Target
	cc     resolver.ClientConn
}

func (r endpointIDResolution) ResolveNow(resolver.ResolveNowOptions) {
	r.cc.UpdateState(resolver.State{Addresses: []resolver.Address{{Addr: r.target.Endpoint()}}})
}

func (endpointIDResolution) Close() {}
