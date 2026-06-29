package h3iroh

import (
	"github.com/tmc/go-iroh/http3"
	"github.com/tmc/go-iroh/iroh"
)

// Conn is an HTTP/3 transport adapter over an iroh connection.
type Conn = http3.Conn

// BidiStream is an HTTP/3 bidirectional stream over iroh.
type BidiStream = http3.BidiStream

// SendStream is an HTTP/3 unidirectional send stream over iroh.
type SendStream = http3.SendStream

// ReceiveStream is an HTTP/3 unidirectional receive stream over iroh.
type ReceiveStream = http3.ReceiveStream

// NewConn adapts c for HTTP/3 transport code.
func NewConn(c *iroh.Conn) *Conn {
	return http3.NewConn(c)
}
