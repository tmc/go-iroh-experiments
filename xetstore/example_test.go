package xetstore_test

import (
	"context"
	"fmt"
	"io"
	"net/netip"
	"time"

	"github.com/tmc/go-iroh-experiments/xetstore"
	"github.com/tmc/go-iroh/blobs"
	"github.com/tmc/go-iroh/iroh"
	"github.com/tmc/go-iroh/netaddr"
)

func ExampleStore_servingBlob() {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	store := xetstore.New()
	hash, err := store.ImportBytes([]byte("xet over iroh"))
	check(err)

	server, err := iroh.Bind(ctx,
		iroh.WithALPNs(blobs.ALPN),
		iroh.WithBindAddr(netip.AddrPortFrom(netip.IPv6Loopback(), 0)),
	)
	check(err)
	defer server.Shutdown(ctx)

	errc := make(chan error, 1)
	go func() {
		conn, err := server.Accept(ctx)
		if err != nil {
			errc <- err
			return
		}
		stream, err := conn.AcceptStream(ctx)
		if err != nil {
			errc <- err
			return
		}
		errc <- blobs.ServeBlob(ctx, stream, blobs.StoreFunc(func(got blobs.Hash) ([]byte, bool) {
			entry, ok, err := store.Get(ctx, got)
			if err != nil || !ok {
				return nil, false
			}
			r, err := entry.DataReader(ctx)
			if err != nil {
				return nil, false
			}
			size, _ := entry.Size()
			data := make([]byte, size)
			if _, err := r.ReadAt(data, 0); err != nil && err != io.EOF {
				return nil, false
			}
			return data, true
		}))
	}()

	client, err := iroh.Bind(ctx, iroh.WithBindAddr(netip.AddrPortFrom(netip.IPv6Loopback(), 0)))
	check(err)
	defer client.Shutdown(ctx)

	conn, err := client.Connect(ctx, netaddr.NewEndpointAddr(server.ID()).WithIP(server.LocalAddr()), blobs.ALPN)
	check(err)
	defer conn.Close()
	stream, err := conn.OpenStreamSync(ctx)
	check(err)
	got, err := blobs.GetBlobBytes(ctx, stream, hash)
	check(err)
	check(<-errc)

	fmt.Println(string(got))
	// Output: xet over iroh
}

func check(err error) {
	if err != nil {
		panic(err)
	}
}
