package x402iroh

import (
	"context"
	"net"
	"net/http"

	"github.com/tmc/go-iroh/iroh"
	"github.com/tmc/x402"
)

// ALPN is the iroh ALPN for x402-paid HTTP: HTTP/1.1 over bidirectional
// iroh streams, one stream per HTTP connection.
const ALPN = "x402/iroh/1"

// Serve serves h over ep's incoming streams. It takes over ep's accept
// loop and blocks until the endpoint shuts down. The endpoint must be
// bound with [ALPN] (or another ALPN the clients use).
func Serve(ep *iroh.Endpoint, h http.Handler) error {
	l, err := ep.ListenStreams()
	if err != nil {
		return err
	}
	return http.Serve(l, h)
}

// NewTransport returns an HTTP transport that carries every request over
// bidirectional streams of conn. Request URLs use the "http" scheme; the
// host part only sets the Host header and is conventionally the server's
// endpoint ID.
func NewTransport(conn *iroh.Conn) *http.Transport {
	return &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return conn.OpenStreamConn(ctx)
		},
	}
}

// NewClient returns an HTTP client over conn that pays x402 challenges
// with payer. A nil payer disables paying.
func NewClient(conn *iroh.Conn, payer x402.Payer) *http.Client {
	return &http.Client{
		Transport: &x402.Transport{Base: NewTransport(conn), Payer: payer},
	}
}
