package grpciroh_test

import (
	"fmt"

	"github.com/tmc/go-iroh-experiments/grpciroh"
)

func Example() {
	// Register grpciroh.ALPN with the server's iroh router. Once an iroh
	// connection is established, pass grpciroh.DialOptions(conn) to gRPC.
	fmt.Println(grpciroh.ALPN)
	// Output: grpc/iroh/1
}
