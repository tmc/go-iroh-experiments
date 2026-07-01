package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"net/netip"
	"os"
	"strings"

	"github.com/tmc/go-iroh-experiments/grpciroh"
	"github.com/tmc/go-iroh-experiments/grpciroh/internal/greeterpb"
	"github.com/tmc/go-iroh/iroh"
	"github.com/tmc/go-iroh/key"
	"github.com/tmc/go-iroh/netaddr"
	"google.golang.org/grpc"
)

type greeterServer struct {
	greeterpb.UnimplementedGreeterServer
}

func (greeterServer) SayHello(ctx context.Context, req *greeterpb.HelloRequest) (*greeterpb.HelloReply, error) {
	return &greeterpb.HelloReply{Message: "hello " + req.Name}, nil
}

func (greeterServer) LotsOfReplies(req *greeterpb.HelloRequest, stream greeterpb.Greeter_LotsOfRepliesServer) error {
	for i := 0; i < 3; i++ {
		if err := stream.Send(&greeterpb.HelloReply{Message: fmt.Sprintf("hello %s %d", req.Name, i)}); err != nil {
			return err
		}
	}
	return nil
}

func (greeterServer) LotsOfGreetings(stream greeterpb.Greeter_LotsOfGreetingsServer) error {
	var names []string
	for {
		req, err := stream.Recv()
		if err == io.EOF {
			return stream.SendAndClose(&greeterpb.HelloReply{Message: "hello " + strings.Join(names, ",")})
		}
		if err != nil {
			return err
		}
		names = append(names, req.Name)
	}
}

func (greeterServer) BidiHello(stream greeterpb.Greeter_BidiHelloServer) error {
	for {
		req, err := stream.Recv()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		if err := stream.Send(&greeterpb.HelloReply{Message: "hello " + req.Name}); err != nil {
			return err
		}
	}
}

func main() {
	mode := flag.String("mode", "server", "server or client")
	peerID := flag.String("peer-id", "", "server EndpointID")
	peerAddr := flag.String("peer-addr", "", "optional server host:port hint")
	name := flag.String("name", "iroh", "name to send")
	flag.Parse()

	ctx := context.Background()
	switch *mode {
	case "server":
		if err := runServer(ctx); err != nil {
			log.Fatal(err)
		}
	case "client":
		if err := runClient(ctx, *peerID, *peerAddr, *name); err != nil {
			log.Fatal(err)
		}
	default:
		fmt.Fprintf(os.Stderr, "unknown mode %q\n", *mode)
		os.Exit(2)
	}
}

func runServer(ctx context.Context) error {
	ep, err := iroh.Bind(ctx,
		iroh.WithALPNs(grpciroh.ALPN),
		iroh.WithBindAddr(netip.AddrPortFrom(netip.IPv6Loopback(), 0)),
	)
	if err != nil {
		return fmt.Errorf("bind: %w", err)
	}
	defer ep.Shutdown(ctx)

	lis, err := ep.ListenStreams()
	if err != nil {
		return fmt.Errorf("listen streams: %w", err)
	}
	defer lis.Close()

	fmt.Printf("endpoint id: %s\n", ep.ID())
	fmt.Printf("local addr: %s\n", ep.LocalAddr())

	srv := grpc.NewServer()
	greeterpb.RegisterGreeterServer(srv, greeterServer{})
	if err := srv.Serve(lis); err != nil {
		return fmt.Errorf("serve: %w", err)
	}
	return nil
}

func runClient(ctx context.Context, peerID, peerAddr, name string) error {
	if peerID == "" {
		return fmt.Errorf("missing -peer-id")
	}
	id, err := key.ParseEndpointID(peerID)
	if err != nil {
		return fmt.Errorf("parse peer id: %w", err)
	}

	ep, err := iroh.Bind(ctx, iroh.WithBindAddr(netip.AddrPortFrom(netip.IPv6Loopback(), 0)))
	if err != nil {
		return fmt.Errorf("bind: %w", err)
	}
	defer ep.Shutdown(ctx)

	addr := netaddr.NewEndpointAddr(id)
	if peerAddr != "" {
		ap, err := netip.ParseAddrPort(peerAddr)
		if err != nil {
			return fmt.Errorf("parse peer addr: %w", err)
		}
		addr = addr.WithIP(ap)
	}
	conn, err := ep.Connect(ctx, addr, grpciroh.ALPN)
	if err != nil {
		return fmt.Errorf("connect: %w", err)
	}
	gc, err := grpciroh.NewClient(conn, id.String())
	if err != nil {
		conn.Close()
		return fmt.Errorf("new client: %w", err)
	}
	defer gc.Close()

	client := greeterpb.NewGreeterClient(gc.ClientConn)
	reply, err := client.SayHello(ctx, &greeterpb.HelloRequest{Name: name})
	if err != nil {
		return fmt.Errorf("say hello: %w", err)
	}
	fmt.Println(reply.Message)

	stream, err := client.LotsOfReplies(ctx, &greeterpb.HelloRequest{Name: name})
	if err != nil {
		return fmt.Errorf("lots of replies: %w", err)
	}
	for {
		reply, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("recv reply: %w", err)
		}
		fmt.Println(reply.Message)
	}
	return nil
}
