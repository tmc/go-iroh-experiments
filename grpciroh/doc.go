// Package grpciroh runs gRPC over an iroh QUIC connection.
//
// The server side needs no adapter code. Bind an iroh endpoint with ALPN,
// call Endpoint.ListenStreams, and pass the listener to grpc.Server.Serve.
//
//	Client side connects to the peer by EndpointID:
//	conn, err := ep.Connect(ctx, addr, grpciroh.ALPN)
//	cc, err := grpc.NewClient(peerID.String(), grpciroh.DialOptions(conn)...)
//
// SECURITY: DialOptions uses gRPC insecure credentials because gRPC adds no
// TLS of its own. The transport is still authenticated and encrypted: iroh
// authenticates peers by Ed25519 EndpointID and encrypts streams at the QUIC
// layer.
package grpciroh
