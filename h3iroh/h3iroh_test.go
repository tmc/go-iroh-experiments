package h3iroh_test

import (
	"context"
	"io"
	"net/netip"
	"testing"
	"time"

	"github.com/tmc/go-iroh-experiments/h3iroh"
	"github.com/tmc/go-iroh/iroh"
	"github.com/tmc/go-iroh/netaddr"
)

func TestConnBidiStream(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	const alpn = "h3iroh-test/1"
	server, err := iroh.Bind(ctx,
		iroh.WithALPNs(alpn),
		iroh.WithBindAddr(netip.AddrPortFrom(netip.IPv6Loopback(), 0)),
	)
	if err != nil {
		t.Fatalf("bind server: %v", err)
	}
	defer server.Shutdown(ctx)

	accepted := make(chan *iroh.Conn, 1)
	errc := make(chan error, 1)
	go func() {
		c, err := server.Accept(ctx)
		if err != nil {
			errc <- err
			return
		}
		accepted <- c
	}()

	client, err := iroh.Bind(ctx, iroh.WithBindAddr(netip.AddrPortFrom(netip.IPv6Loopback(), 0)))
	if err != nil {
		t.Fatalf("bind client: %v", err)
	}
	defer client.Shutdown(ctx)

	clientConn, err := client.Connect(ctx, netaddr.NewEndpointAddr(server.ID()).WithIP(server.LocalAddr()), alpn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer clientConn.Close()

	var serverConn *iroh.Conn
	select {
	case serverConn = <-accepted:
	case err := <-errc:
		t.Fatalf("accept: %v", err)
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	defer serverConn.Close()

	serverH3 := h3iroh.NewConn(serverConn)
	done := make(chan error, 1)
	go func() {
		s, err := serverH3.AcceptBidi(ctx)
		if err != nil {
			done <- err
			return
		}
		_, err = io.Copy(s, s)
		done <- err
	}()

	stream, err := h3iroh.NewConn(clientConn).OpenBidi(ctx)
	if err != nil {
		t.Fatalf("open bidi: %v", err)
	}
	if _, err := stream.Write([]byte("h3")); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, 2)
	if _, err := io.ReadFull(stream, buf); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if string(buf) != "h3" {
		t.Fatalf("echo = %q, want h3", buf)
	}
	if err := stream.Close(); err != nil {
		t.Fatalf("close stream: %v", err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("server stream: %v", err)
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
}
