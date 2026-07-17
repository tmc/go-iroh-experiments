// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"

	"github.com/tmc/go-iroh-experiments/enclaveiroh"
	"github.com/tmc/go-iroh/iroh"
)

// alpn is the ALPN for the echo demo: newline-delimited lines echoed back over
// a single bidirectional iroh stream.
const alpn = "enclaveiroh/echo/1"

// serveEcho accepts connections on ep and serves the echo protocol on each,
// echoing newline-delimited lines back uppercased until the endpoint closes. It
// blocks. Accepting whole connections (rather than the flattened streams of
// ListenStreams) keeps the per-connection boundary the attestation handshake
// needs — the first stream of a connection is the handshake, later streams are
// application streams.
//
// When hsCfg is non-nil, every connection runs the T6 attestation handshake on
// its first bidirectional stream before any application stream is served; a
// connection whose handshake fails is dropped without reaching the echo loop.
func serveEcho(ctx context.Context, ep *iroh.Endpoint, report io.Writer, hsCfg *enclaveiroh.HandshakeConfig) error {
	for {
		conn, err := ep.Accept(ctx)
		if err != nil {
			return err
		}
		go handleConn(ctx, conn, report, hsCfg)
	}
}

// handleConn serves one peer connection. When hsCfg is set, the first
// bidirectional stream carries the attestation handshake (T6, see ATTEST.md):
// it must complete before any application stream is accepted, and a failure
// closes the connection. Later streams are application (echo) streams.
func handleConn(ctx context.Context, conn *iroh.Conn, report io.Writer, hsCfg *enclaveiroh.HandshakeConfig) {
	defer conn.Close()
	fmt.Fprintf(report, "conn: peer %s (alpn %s)\n", conn.RemoteID(), conn.ALPN())

	if hsCfg != nil {
		att, err := enclaveiroh.Handshake(ctx, conn, *hsCfg)
		if err != nil {
			fmt.Fprintf(report, "conn: peer %s rejected: %v\n", conn.RemoteID(), err)
			return
		}
		logPeerAttestation(report, conn.RemoteID(), att)
	}

	for {
		stream, err := conn.AcceptStreamConn(ctx)
		if err != nil {
			return
		}
		go handleEcho(stream, report)
	}
}

// handleEcho echoes one connection's lines and closes it.
func handleEcho(conn net.Conn, report io.Writer) {
	defer conn.Close()
	fmt.Fprintf(report, "echo: stream from %s\n", conn.RemoteAddr())
	sc := bufio.NewScanner(conn)
	for sc.Scan() {
		line := sc.Bytes()
		out := make([]byte, len(line)+1)
		for i, b := range line {
			if b >= 'a' && b <= 'z' {
				b -= 'a' - 'A'
			}
			out[i] = b
		}
		out[len(line)] = '\n'
		if _, err := conn.Write(out); err != nil {
			return
		}
	}
}

// echoOverConn opens an application stream on an already-connected (and, when
// attestation is enabled, already-attested) connection, sends each message on
// its own line, and returns the echoed replies in order. The caller owns conn's
// lifetime, including running the handshake before this is called.
func echoOverConn(ctx context.Context, conn *iroh.Conn, messages []string) ([]string, error) {
	stream, err := conn.OpenStreamConn(ctx)
	if err != nil {
		return nil, fmt.Errorf("open stream: %w", err)
	}
	defer stream.Close()

	replies := make([]string, 0, len(messages))
	sc := bufio.NewScanner(stream)
	for _, m := range messages {
		if _, err := fmt.Fprintln(stream, m); err != nil {
			return replies, fmt.Errorf("write: %w", err)
		}
		if !sc.Scan() {
			if err := sc.Err(); err != nil {
				return replies, fmt.Errorf("read: %w", err)
			}
			return replies, io.ErrUnexpectedEOF
		}
		replies = append(replies, sc.Text())
	}
	return replies, nil
}
