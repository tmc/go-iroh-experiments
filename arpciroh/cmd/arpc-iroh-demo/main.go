package main

import (
	"context"
	"fmt"
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

func main() {
	ctx := context.Background()

	// INIT

	// state machine
	netSrc, err := am.NewCommon(ctx, "iroh", states.ExampleSchema, ss.Names(), nil, nil, nil)
	if err != nil {
		panic(err)
	}
	amhelp.MachDebugEnv(netSrc)

	// server init
	srvKey, err := key.GenerateSecretKey()
	if err != nil {
		panic(err)
	}
	sOpts := &amiroh.ServerOpts{
		ServerOpts: arpc.ServerOpts{
			Parent: netSrc,
		},
		SecretKey:  &srvKey,
	}
	s, srvEp, err := amiroh.NewServer(ctx, "127.0.0.1:0", netSrc.Id(), netSrc, sOpts)
	if err != nil {
		panic(err)
	}
	amhelp.MachDebugEnv(s.Mach)

	// let it settle
	time.Sleep(10 * time.Millisecond)
	serverAddr := srvEp.LocalAddr()
	addr := netaddr.NewEndpointAddr(srvEp.ID()).WithIP(serverAddr)
	ticket := endpointticket.Encode(addr)

	// client init
	c, _, err := amiroh.NewClient(ctx, ticket, netSrc.Id(), states.ExampleSchema, nil)
	if err != nil {
		panic(err)
	}
	amhelp.MachDebugEnv(c.Mach)

	// START

	// server start
	s.Start(nil)
	amhelp.WaitForAll(ctx, time.Second,
		s.Mach.When1(ssrpc.ServerStates.RpcReady, ctx))

	// client start
	c.Start(nil)
	amhelp.WaitForAll(ctx, time.Second,
		c.Mach.When1(ssrpc.ClientStates.Ready, ctx),
		s.Mach.When1(ssrpc.ServerStates.Ready, ctx))

	// CHANGE STATE

	netSrc.Add1(ss.Foo, nil)
	netSrc.Add1(ss.Bar, nil)

	<-c.NetMach.When1(ss.Bar, nil)
	<-c.NetMach.WhenNot1(ss.Foo, nil)

	fmt.Printf("netSrc  => %s\n", netSrc)
	fmt.Printf("netMach => %s\n", c.NetMach)
}