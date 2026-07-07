package main

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/tmc/go-iroh/iroh"
	"github.com/tmc/go-iroh/key"
	"github.com/tmc/go-iroh/netaddr"
)

const alpn = "directpath-probe/1"

func main() {
	if err := run(context.Background(), os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return errors.New("usage: directpath-probe inspect|listen|dial")
	}
	switch args[0] {
	case "inspect":
		return runInspect(args[1:])
	case "listen":
		return runListen(ctx, args[1:])
	case "dial":
		return runDial(ctx, args[1:])
	default:
		return fmt.Errorf("unknown command %q", args[0])
	}
}

func runInspect(args []string) error {
	fs := flag.NewFlagSet("inspect", flag.ExitOnError)
	if err := fs.Parse(args); err != nil {
		return err
	}
	ifaces, err := net.Interfaces()
	if err != nil {
		return fmt.Errorf("list interfaces: %w", err)
	}
	for _, iface := range ifaces {
		addrs, err := iface.Addrs()
		if err != nil {
			fmt.Printf("iface=%s error=%v\n", iface.Name, err)
			continue
		}
		for _, addr := range addrs {
			ip, prefix, ok := parseInterfaceAddr(addr)
			if !ok {
				continue
			}
			fmt.Printf("iface=%s flags=%s ip=%s prefix=%d family=%s scope=%s tailscale=%t\n",
				iface.Name, iface.Flags, ip, prefix, family(ip), scope(ip), isTailscale(ip))
		}
	}
	return nil
}

func runListen(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("listen", flag.ExitOnError)
	bind := fs.String("bind", ":0", "UDP address to bind")
	timeout := fs.Duration("timeout", 0, "optional listen timeout")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, *timeout)
		defer cancel()
	}
	ap, err := parseBind(*bind)
	if err != nil {
		return err
	}
	ep, err := iroh.Bind(ctx, iroh.WithALPNs(alpn), iroh.WithBindAddr(ap), iroh.WithoutRelayTransports())
	if err != nil {
		return fmt.Errorf("bind endpoint: %w", err)
	}
	defer ep.Shutdown(context.Background())
	fmt.Printf("id %s\n", ep.ID())
	fmt.Printf("addr %s\n", ep.LocalAddr())
	fmt.Printf("alpn %s\n", alpn)
	conn, err := ep.Accept(ctx)
	if err != nil {
		return fmt.Errorf("accept connection: %w", err)
	}
	defer conn.Close()
	fmt.Printf("accepted remote=%s remote-addr=%s local-addr=%s\n", conn.RemoteID(), conn.RemoteAddr(), conn.LocalAddr())
	stream, err := conn.AcceptStream(ctx)
	if err != nil {
		return fmt.Errorf("accept stream: %w", err)
	}
	defer stream.Close()
	n, err := echoFramed(stream)
	if err != nil {
		return fmt.Errorf("echo stream: %w", err)
	}
	fmt.Printf("echoed bytes=%d\n", n)
	printConn(conn)
	return nil
}

func runDial(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("dial", flag.ExitOnError)
	peerID := fs.String("peer-id", "", "peer endpoint id")
	peerIP := fs.String("peer-ip", "", "peer direct UDP address")
	n := fs.Int64("n", 64<<10, "bytes to send")
	timeout := fs.Duration("timeout", 10*time.Second, "dial and I/O timeout")
	bind := fs.String("bind", ":0", "local UDP address to bind")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *peerID == "" || *peerIP == "" {
		return errors.New("peer-id and peer-ip are required")
	}
	id, err := key.ParseEndpointID(*peerID)
	if err != nil {
		return fmt.Errorf("parse peer id: %w", err)
	}
	peer, err := netip.ParseAddrPort(*peerIP)
	if err != nil {
		return fmt.Errorf("parse peer ip: %w", err)
	}
	ap, err := parseBind(*bind)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, *timeout)
	defer cancel()
	ep, err := iroh.Bind(ctx, iroh.WithBindAddr(ap), iroh.WithoutRelayTransports())
	if err != nil {
		return fmt.Errorf("bind endpoint: %w", err)
	}
	defer ep.Shutdown(context.Background())
	addr := netaddr.NewEndpointAddr(id).WithIP(peer)
	start := time.Now()
	conn, err := ep.Connect(ctx, addr, alpn)
	if err != nil {
		return fmt.Errorf("connect direct: %w", err)
	}
	defer conn.Close()
	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		return fmt.Errorf("open stream: %w", err)
	}
	defer stream.Close()
	if deadline, ok := ctx.Deadline(); ok {
		stream.SetDeadline(deadline)
	}
	var header [8]byte
	binary.BigEndian.PutUint64(header[:], uint64(*n))
	if _, err := stream.Write(header[:]); err != nil {
		return fmt.Errorf("write size: %w", err)
	}
	sent, err := io.CopyN(stream, rand.Reader, *n)
	if err != nil {
		return fmt.Errorf("write payload: %w", err)
	}
	var echoHeader [8]byte
	if _, err := io.ReadFull(stream, echoHeader[:]); err != nil {
		return fmt.Errorf("read echo size: %w", err)
	}
	if binary.BigEndian.Uint64(echoHeader[:]) != uint64(sent) {
		return fmt.Errorf("echo size %d, want %d", binary.BigEndian.Uint64(echoHeader[:]), sent)
	}
	got, err := io.CopyN(io.Discard, stream, sent)
	if err != nil {
		return fmt.Errorf("read echo: %w", err)
	}
	if got != sent {
		return fmt.Errorf("echo bytes %d, want %d", got, sent)
	}
	fmt.Printf("connected elapsed=%s bytes=%d\n", time.Since(start).Round(time.Millisecond), sent)
	printConn(conn)
	return nil
}

func echoFramed(stream io.ReadWriter) (int64, error) {
	var header [8]byte
	if _, err := io.ReadFull(stream, header[:]); err != nil {
		return 0, fmt.Errorf("read size: %w", err)
	}
	u := binary.BigEndian.Uint64(header[:])
	if u > uint64(1<<62) {
		return 0, errors.New("size too large")
	}
	n := int64(u)
	if _, err := stream.Write(header[:]); err != nil {
		return 0, fmt.Errorf("write size: %w", err)
	}
	written, err := io.CopyN(stream, io.LimitReader(stream, n), n)
	if err != nil {
		return written, fmt.Errorf("echo payload: %w", err)
	}
	return written, nil
}

func printConn(conn *iroh.Conn) {
	stats := conn.Stats()
	fmt.Printf("conn remote=%s local-addr=%s remote-addr=%s rtt=%s sent=%d received=%d lost-packets=%d lost-bytes=%d\n",
		conn.RemoteID(), conn.LocalAddr(), conn.RemoteAddr(), stats.SmoothedRTT,
		stats.BytesSent, stats.BytesReceived, stats.PacketsLost, stats.BytesLost)
	for _, p := range conn.Paths() {
		fmt.Printf("path id=%d selected=%t validated=%t relayed=%t", p.ID, p.Selected, p.Validated, p.Relayed)
		if p.HasAddr {
			fmt.Printf(" addr=%s", p.Addr)
		}
		if p.HasRTT {
			fmt.Printf(" rtt=%s", p.RTT)
		}
		if p.HasBytesSent {
			fmt.Printf(" sent=%d", p.BytesSent)
		}
		if p.HasBytesReceived {
			fmt.Printf(" received=%d", p.BytesReceived)
		}
		if p.HasLoss {
			fmt.Printf(" lost-packets=%d lost-bytes=%d", p.LostPackets, p.LostBytes)
		}
		fmt.Println()
	}
}

func parseBind(s string) (netip.AddrPort, error) {
	host, port, err := net.SplitHostPort(s)
	if err != nil {
		if strings.HasPrefix(s, ":") {
			host = ""
			port = strings.TrimPrefix(s, ":")
		} else {
			return netip.AddrPort{}, fmt.Errorf("parse bind address: %w", err)
		}
	}
	p, err := strconv.ParseUint(port, 10, 16)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("parse bind port: %w", err)
	}
	ip := netip.IPv6Unspecified()
	if host != "" {
		ip, err = netip.ParseAddr(host)
		if err != nil {
			return netip.AddrPort{}, fmt.Errorf("parse bind host: %w", err)
		}
	}
	return netip.AddrPortFrom(ip, uint16(p)), nil
}

func parseInterfaceAddr(addr net.Addr) (netip.Addr, int, bool) {
	prefix, err := netip.ParsePrefix(addr.String())
	if err == nil {
		return prefix.Addr(), prefix.Bits(), true
	}
	ip, err := netip.ParseAddr(addr.String())
	if err != nil {
		return netip.Addr{}, 0, false
	}
	if ip.Is4() {
		return ip, 32, true
	}
	return ip, 128, true
}

func family(ip netip.Addr) string {
	if ip.Is4() {
		return "ipv4"
	}
	return "ipv6"
}

func scope(ip netip.Addr) string {
	switch {
	case ip.IsLoopback():
		return "loopback"
	case ip.IsLinkLocalUnicast():
		return "link-local"
	case isCGNAT(ip):
		return "cgnat"
	case ip.IsPrivate():
		return "private"
	case ip.IsGlobalUnicast():
		return "global"
	default:
		return "other"
	}
}

func isTailscale(ip netip.Addr) bool {
	return ip.Is4() && ip.As4()[0] == 100 || ip.Is6() && strings.HasPrefix(ip.String(), "fd7a:115c:a1e0:")
}

func isCGNAT(ip netip.Addr) bool {
	if !ip.Is4() {
		return false
	}
	a := ip.As4()
	return a[0] == 100 && a[1]&0xc0 == 0x40
}
