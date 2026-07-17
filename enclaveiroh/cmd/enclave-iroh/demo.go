// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"

	"github.com/tmc/go-iroh/iroh"
	"github.com/tmc/go-iroh/netaddr"
)

// alpn is the ALPN for the echo demo: newline-delimited lines echoed back over
// a single bidirectional iroh stream.
const alpn = "enclaveiroh/echo/1"

// serveEcho accepts streams on ep and echoes each newline-delimited line back,
// uppercased, until the endpoint closes. It blocks.
func serveEcho(ep *iroh.Endpoint, report io.Writer) error {
	l, err := ep.ListenStreams()
	if err != nil {
		return err
	}
	defer l.Close()
	for {
		conn, err := l.Accept()
		if err != nil {
			return err
		}
		go handleEcho(conn, report)
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

// dialEcho connects to addr's endpoint, sends each message on its own line, and
// returns the echoed replies in order.
func dialEcho(ctx context.Context, ep *iroh.Endpoint, addr netaddr.EndpointAddr, messages []string) ([]string, error) {
	conn, err := ep.Connect(ctx, addr, alpn)
	if err != nil {
		return nil, fmt.Errorf("connect: %w", err)
	}
	defer conn.Close()
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
