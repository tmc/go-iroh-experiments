package arpciroh

import (
	"context"
	"testing"
	"time"

	amhelp "github.com/pancsta/asyncmachine-go/pkg/helpers"
	am "github.com/pancsta/asyncmachine-go/pkg/machine"
	arpc "github.com/pancsta/asyncmachine-go/pkg/rpc"
	amiroh "github.com/pancsta/asyncmachine-go/pkg/rpc/iroh"
	ssrpc "github.com/pancsta/asyncmachine-go/pkg/rpc/states"
	"github.com/tmc/go-iroh/endpointticket"
	"github.com/tmc/go-iroh/key"
	"github.com/tmc/go-iroh/netaddr"

	"arpciroh/states"
)

var ss = states.ExampleStates

func TestIrohSync(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	netSrc, err := am.NewCommon(ctx, "test-iroh", states.ExampleSchema, ss.Names(), nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer netSrc.Dispose()

	srvKey, err := key.GenerateSecretKey()
	if err != nil {
		t.Fatal(err)
	}
	s, srvEp, err := amiroh.NewServer(ctx, "127.0.0.1:0", netSrc.Id(), netSrc,
		&amiroh.ServerOpts{
			ServerOpts: arpc.ServerOpts{Parent: netSrc},
			SecretKey:  &srvKey,
		})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Mach.Dispose()

	addr := netaddr.NewEndpointAddr(srvEp.ID()).WithIP(srvEp.LocalAddr())
	c, _, err := amiroh.NewClient(ctx, endpointticket.Encode(addr), netSrc.Id(), states.ExampleSchema, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Mach.Dispose()

	s.Start(nil)
	c.Start(nil)
	err = amhelp.WaitForAll(ctx, 5*time.Second,
		s.Mach.When1(ssrpc.ServerStates.RpcReady, ctx),
		c.Mach.When1(ssrpc.ClientStates.Ready, ctx),
		s.Mach.When1(ssrpc.ServerStates.Ready, ctx))
	if err != nil {
		t.Fatal(err)
	}

	netSrc.Add1(ss.Foo, nil)
	netSrc.Add1(ss.Bar, nil)

	select {
	case <-c.NetMach.When1(ss.Bar, ctx):
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	select {
	case <-c.NetMach.WhenNot1(ss.Foo, ctx):
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}

	if !netSrc.Is1(ss.Bar) || !c.NetMach.Is1(ss.Bar) {
		t.Fatalf("state not synced: src=%s net=%s", netSrc, c.NetMach)
	}
}
