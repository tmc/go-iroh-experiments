// Command twobox-directpath is a two-host proof harness for direct-path
// selection with relay coordination enabled (it proved the remote ticket-IP
// direct-path fix, go-iroh commit 2f6c309). The server binds a concrete
// address and prints its EndpointID + IP; the client dials that ID+IP with
// relay enabled, moves a payload over a stream, and reports whether
// Conn.Paths() selected a VALIDATED DIRECT (non-relayed) path plus throughput.
//
// It complements directpath-probe: the probe is relay-free and isolates
// candidate/bind/validation problems, while this harness checks that a
// relay-coordinated connection still upgrades to a direct path and measures
// its throughput.
package main

import (
	"context"
	"crypto/rand"
	"flag"
	"fmt"
	"io"
	"log"
	"net/netip"
	"os"
	"time"

	"github.com/tmc/go-iroh/iroh"
	"github.com/tmc/go-iroh/key"
	"github.com/tmc/go-iroh/netaddr"
	"github.com/tmc/go-iroh/relay"
)

const alpn = "twobox-directpath/0"

func main() {
	mode := flag.String("mode", "", "server|client")
	bind := flag.String("bind", "", "concrete bind addr host:port (port 0 = ephemeral)")
	id := flag.String("id", "", "client: server EndpointID")
	peer := flag.String("peer", "", "client: server IP addr host:port")
	relayURL := flag.String("relayurl", "", "client: server relay URL for coordination fallback")
	bytesN := flag.Int("bytes", 2_500_000, "client: payload bytes to transfer")
	useRelay := flag.Bool("relay", true, "enable default relay for coordination")
	flag.Parse()

	// Server runs until killed; client bounds itself.
	var ctx context.Context
	var cancel context.CancelFunc
	if *mode == "client" {
		ctx, cancel = context.WithTimeout(context.Background(), 5*time.Minute)
	} else {
		ctx, cancel = context.WithCancel(context.Background())
	}
	defer cancel()

	relayMode := relay.ModeDisabled()
	if *useRelay {
		relayMode = relay.ModeDefault()
	}

	ba, err := netip.ParseAddrPort(*bind)
	if err != nil {
		log.Fatalf("bad -bind %q: %v", *bind, err)
	}

	switch *mode {
	case "server":
		runServer(ctx, ba, relayMode)
	case "client":
		runClient(ctx, ba, relayMode, *id, *peer, *relayURL, *bytesN)
	default:
		log.Fatalf("mode must be server or client")
	}
}

func runServer(ctx context.Context, ba netip.AddrPort, rm relay.Mode) {
	sk, _ := key.GenerateSecretKey()
	ep, err := iroh.Bind(ctx, iroh.WithSecretKey(sk), iroh.WithALPNs(alpn),
		iroh.WithBindAddr(ba), iroh.WithRelayMode(rm), iroh.WithNetReport())
	if err != nil {
		log.Fatalf("bind: %v", err)
	}
	defer ep.Shutdown(context.Background())

	// Report our dialable coordinates for the client.
	fmt.Printf("SERVER_ID=%s\n", ep.ID())
	fmt.Printf("SERVER_LOCAL=%s\n", ep.LocalAddr())
	fmt.Printf("SERVER_ADDR=%s\n", ep.Addr())
	os.Stdout.Sync()

	for {
		conn, err := ep.Accept(ctx)
		if err != nil {
			log.Printf("accept done: %v", err)
			return
		}
		go serve(ctx, conn)
	}
}

func serve(ctx context.Context, conn *iroh.Conn) {
	log.Printf("serve: conn accepted remote=%v", conn.RemoteAddr())
	st, err := conn.AcceptStream(ctx)
	if err != nil {
		log.Printf("accept stream: %v", err)
		return
	}
	log.Printf("serve: stream accepted")
	// Sink: drain the whole stream, then reply with an 8-byte count so the
	// client can time a full one-way transfer without a duplex deadlock.
	n, err := io.Copy(io.Discard, st)
	if err != nil {
		log.Printf("sink: %v", err)
	}
	var ack [8]byte
	for i := 0; i < 8; i++ {
		ack[i] = byte(n >> (8 * i))
	}
	if _, werr := st.Write(ack[:]); werr != nil {
		log.Printf("ack write: %v", werr)
	}
	log.Printf("served %d bytes", n)
}

func runClient(ctx context.Context, ba netip.AddrPort, rm relay.Mode, idStr, peer, relayURLStr string, n int) {
	sk, _ := key.GenerateSecretKey()
	ep, err := iroh.Bind(ctx, iroh.WithSecretKey(sk), iroh.WithALPNs(alpn),
		iroh.WithBindAddr(ba), iroh.WithRelayMode(rm), iroh.WithRelayFirstDial(), iroh.WithNetReport())
	if err != nil {
		log.Fatalf("bind: %v", err)
	}
	defer ep.Shutdown(context.Background())

	eid, err := key.ParseEndpointID(idStr)
	if err != nil {
		log.Fatalf("parse id: %v", err)
	}
	pa, err := netip.ParseAddrPort(peer)
	if err != nil {
		log.Fatalf("parse peer: %v", err)
	}
	addr := netaddr.NewEndpointAddr(eid).WithIP(pa)
	if relayURLStr != "" {
		ru, err := netaddr.ParseRelayURL(relayURLStr)
		if err != nil {
			log.Fatalf("parse relayurl: %v", err)
		}
		addr = addr.WithRelayURL(ru)
	}

	conn, err := ep.Connect(ctx, addr, alpn)
	if err != nil {
		log.Fatalf("connect: %v", err)
	}
	defer conn.CloseWithError(0, "")

	payload := make([]byte, n)
	rand.Read(payload)

	// Wait for the socket path selector to choose a validated DIRECT
	// (non-relayed) path, so the transfer rides the direct path.
	fmt.Printf("MULTIPATH_NEGOTIATED=%v\n", conn.MultipathNegotiated())
	dumpPaths(conn, "on-connect")
	waitDirectSelected(ctx, conn, 90*time.Second)
	dumpPaths(conn, "pre-transfer")

	st, err := conn.OpenStreamSync(ctx)
	if err != nil {
		log.Fatalf("open stream: %v", err)
	}
	if deadline, ok := ctx.Deadline(); ok {
		if err := st.SetDeadline(deadline); err != nil {
			log.Fatalf("set stream deadline: %v", err)
		}
	}

	start := time.Now()
	// Periodic path dump so a stalled transfer shows which path is selected
	// and whether bytes are moving (per-path counters), without debug logs.
	dumpDone := make(chan struct{})
	go func() {
		t := time.NewTicker(15 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-dumpDone:
				return
			case <-ctx.Done():
				return
			case <-t.C:
				dumpPaths(conn, fmt.Sprintf("t+%s", time.Since(start).Truncate(time.Second)))
			}
		}
	}()
	for off := 0; off < len(payload); {
		end := off + 64*1024
		if end > len(payload) {
			end = len(payload)
		}
		nw, err := st.Write(payload[off:end])
		if err != nil {
			log.Fatalf("write: %v", err)
		}
		off += nw
	}
	close(dumpDone)
	if err := st.Close(); err != nil {
		log.Fatalf("close send: %v", err)
	}
	// Read the server's 8-byte received-count ack (confirms full delivery).
	var ack [8]byte
	if _, err := io.ReadFull(st, ack[:]); err != nil {
		log.Fatalf("read ack: %v", err)
	}
	var got int64
	for i := 0; i < 8; i++ {
		got |= int64(ack[i]) << (8 * i)
	}
	elapsed := time.Since(start)
	if got != int64(n) {
		log.Fatalf("server received %d bytes, sent %d", got, n)
	}
	mbps := (float64(n) / (1024 * 1024)) / elapsed.Seconds()

	dumpPaths(conn, "post-transfer")
	fmt.Printf("RESULT bytes=%d rtt_echo=%s MBps=%.2f\n", n, elapsed, mbps)

	// Verdict.
	var directValidated, directSelected bool
	for _, p := range conn.Paths() {
		if p.HasAddr && !p.Relayed && p.Validated {
			directValidated = true
			if p.Selected {
				directSelected = true
			}
		}
	}
	fmt.Printf("VERDICT direct_validated=%v direct_selected=%v\n", directValidated, directSelected)
}

// waitDirectSelected blocks until a validated non-relayed path is selected.
func waitDirectSelected(ctx context.Context, conn *iroh.Conn, timeout time.Duration) {
	start := time.Now()
	deadline := start.Add(timeout)
	for time.Now().Before(deadline) {
		for _, p := range conn.Paths() {
			if p.HasAddr && !p.Relayed && p.Validated && p.Selected {
				fmt.Printf("DIRECT_SELECTED after %s addr=%s\n",
					time.Since(start).Truncate(time.Millisecond), p.Addr.String())
				return
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(500 * time.Millisecond):
		}
	}
	fmt.Println("DIRECT_SELECTED=timeout (no direct path selected in window)")
}

func dumpPaths(conn *iroh.Conn, label string) {
	fmt.Printf("PATHS[%s]:\n", label)
	for _, p := range conn.Paths() {
		addr := "?"
		if p.HasAddr {
			addr = p.Addr.String()
		}
		fmt.Printf("  id=%d validated=%v selected=%v relayed=%v addr=%s rtt=%s sent=%d recv=%d\n",
			p.ID, p.Validated, p.Selected, p.Relayed, addr, p.RTT, p.BytesSent, p.BytesReceived)
	}
}
