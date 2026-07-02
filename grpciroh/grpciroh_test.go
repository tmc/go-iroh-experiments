package grpciroh_test

import (
	"context"
	"fmt"
	"io"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/tmc/go-iroh-experiments/grpciroh"
	"github.com/tmc/go-iroh-experiments/grpciroh/internal/greeterpb"
	"github.com/tmc/go-iroh/iroh"
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

func TestUnary(t *testing.T) {
	// newTestClient checks conn.RemoteID against the server identity on setup.
	ctx, gc, _, cleanup := newTestClient(t)
	defer cleanup()

	reply, err := gc.SayHello(ctx, &greeterpb.HelloRequest{Name: "iroh"})
	if err != nil {
		t.Fatalf("SayHello: %v", err)
	}
	if reply.Message != "hello iroh" {
		t.Fatalf("SayHello = %q, want hello iroh", reply.Message)
	}
}

func TestServerStream(t *testing.T) {
	ctx, gc, _, cleanup := newTestClient(t)
	defer cleanup()

	stream, err := gc.LotsOfReplies(ctx, &greeterpb.HelloRequest{Name: "x"})
	if err != nil {
		t.Fatalf("LotsOfReplies: %v", err)
	}
	var got []string
	for {
		reply, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("recv: %v", err)
		}
		got = append(got, reply.Message)
	}
	want := []string{"hello x 0", "hello x 1", "hello x 2"}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("LotsOfReplies = %q, want %q", got, want)
	}
}

func TestClientStream(t *testing.T) {
	ctx, gc, _, cleanup := newTestClient(t)
	defer cleanup()

	stream, err := gc.LotsOfGreetings(ctx)
	if err != nil {
		t.Fatalf("LotsOfGreetings: %v", err)
	}
	for _, name := range []string{"a", "b", "c"} {
		if err := stream.Send(&greeterpb.HelloRequest{Name: name}); err != nil {
			t.Fatalf("send %q: %v", name, err)
		}
	}
	reply, err := stream.CloseAndRecv()
	if err != nil {
		t.Fatalf("CloseAndRecv: %v", err)
	}
	if reply.Message != "hello a,b,c" {
		t.Fatalf("LotsOfGreetings = %q, want hello a,b,c", reply.Message)
	}
}

func TestBidi(t *testing.T) {
	ctx, gc, _, cleanup := newTestClient(t)
	defer cleanup()

	stream, err := gc.BidiHello(ctx)
	if err != nil {
		t.Fatalf("BidiHello: %v", err)
	}
	for _, name := range []string{"one", "two", "three"} {
		if err := stream.Send(&greeterpb.HelloRequest{Name: name}); err != nil {
			t.Fatalf("send %q: %v", name, err)
		}
		reply, err := stream.Recv()
		if err != nil {
			t.Fatalf("recv %q: %v", name, err)
		}
		if reply.Message != "hello "+name {
			t.Fatalf("BidiHello = %q, want hello %s", reply.Message, name)
		}
	}
	if err := stream.CloseSend(); err != nil {
		t.Fatalf("CloseSend: %v", err)
	}
	if _, err := stream.Recv(); err != io.EOF {
		t.Fatalf("final Recv err = %v, want EOF", err)
	}
}

func newTestClient(t *testing.T) (context.Context, greeterpb.GreeterClient, *iroh.Conn, func()) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	server, err := iroh.Bind(ctx,
		iroh.WithALPNs(grpciroh.ALPN),
		iroh.WithBindAddr(netip.AddrPortFrom(netip.IPv6Loopback(), 0)),
	)
	if err != nil {
		cancel()
		t.Fatalf("bind server: %v", err)
	}
	lis, err := server.ListenStreams()
	if err != nil {
		server.Shutdown(ctx)
		cancel()
		t.Fatalf("listen streams: %v", err)
	}
	srv := grpc.NewServer()
	greeterpb.RegisterGreeterServer(srv, greeterServer{})
	servec := make(chan error, 1)
	go func() {
		servec <- srv.Serve(lis)
	}()

	client, err := iroh.Bind(ctx, iroh.WithBindAddr(netip.AddrPortFrom(netip.IPv6Loopback(), 0)))
	if err != nil {
		srv.Stop()
		lis.Close()
		server.Shutdown(ctx)
		cancel()
		t.Fatalf("bind client: %v", err)
	}
	conn, err := client.Connect(ctx, netaddr.NewEndpointAddr(server.ID()).WithIP(server.LocalAddr()), grpciroh.ALPN)
	if err != nil {
		client.Shutdown(ctx)
		srv.Stop()
		lis.Close()
		server.Shutdown(ctx)
		cancel()
		t.Fatalf("connect: %v", err)
	}
	if !conn.RemoteID().Equal(server.ID()) {
		conn.Close()
		client.Shutdown(ctx)
		srv.Stop()
		lis.Close()
		server.Shutdown(ctx)
		cancel()
		t.Fatalf("remote id = %v, want %v", conn.RemoteID(), server.ID())
	}
	cc, err := grpc.NewClient(server.ID().String(), grpciroh.DialOptions(conn)...)
	if err != nil {
		conn.Close()
		client.Shutdown(ctx)
		srv.Stop()
		lis.Close()
		server.Shutdown(ctx)
		cancel()
		t.Fatalf("new client: %v", err)
	}
	cleanup := func() {
		cc.Close()
		conn.Close()
		client.Shutdown(ctx)
		srv.GracefulStop()
		lis.Close()
		select {
		case err := <-servec:
			if err != nil && err != grpc.ErrServerStopped {
				t.Errorf("serve: %v", err)
			}
		case <-ctx.Done():
			t.Errorf("serve did not stop: %v", ctx.Err())
		}
		server.Shutdown(ctx)
		cancel()
	}
	return ctx, greeterpb.NewGreeterClient(cc), conn, cleanup
}
