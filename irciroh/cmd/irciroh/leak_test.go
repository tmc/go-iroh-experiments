package main

import (
	"context"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/tmc/go-iroh-experiments/irciroh"
)

// TestBridgeLeavesNothingRunning drives two bridges through a public
// and a sealed channel, a private message and a QUIT, shuts them down,
// and checks that every goroutine they started has gone.
func TestBridgeLeavesNothingRunning(t *testing.T) {
	if testing.Short() {
		t.Skip("network test")
	}
	base := runtime.NumGoroutine()
	t.Run("session", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()
		aliceAddr, bobAddr := startBridge(t, ctx), startBridge(t, ctx)

		alice := dialIRC(t, aliceAddr)
		alice.register("alice")
		alice.send("JOIN #leak")
		alice.expect(" 366 ", "#leak")
		alice.send("TICKET #leak")
		_, params := parseLine(alice.expect("NOTICE", irciroh.TicketKind))
		pub := params[len(params)-1]
		alice.send("JOIN #vault " + sealKey)
		_, params = parseLine(alice.expect("NOTICE", irciroh.TicketKind))
		sealed := params[len(params)-1]

		bob := dialIRC(t, bobAddr)
		bob.register("bob")
		bob.send("JOIN #leak " + pub)
		bob.expect(" 366 ", "#leak")
		bob.send("JOIN #vault " + sealed)
		bob.expect("bob!", "JOIN #vault")
		alice.expect("JOIN #vault")
		bob.send("PRIVMSG #leak :public")
		alice.expect("PRIVMSG #leak", "public")
		bob.send("PRIVMSG #vault :sealed")
		alice.expect("PRIVMSG #vault", "sealed")
		bob.send("PRIVMSG alice :private")
		alice.expect("PRIVMSG alice", "private")
		bob.send("PART #leak")
		bob.send("QUIT :bye")
		bob.expect("ERROR")
		alice.send("QUIT")
		alice.expect("ERROR")
	})
	deadline := time.Now().Add(15 * time.Second)
	for runtime.NumGoroutine() > base {
		if time.Now().After(deadline) {
			buf := make([]byte, 1<<20)
			buf = buf[:runtime.Stack(buf, true)]
			var ours []string
			for _, g := range strings.Split(string(buf), "\n\n") {
				if strings.Contains(g, "irciroh") && !strings.Contains(g, "testing.tRunner") {
					ours = append(ours, g)
				}
			}
			t.Fatalf("%d goroutines, started with %d:\n\n%s", runtime.NumGoroutine(), base, strings.Join(ours, "\n\n"))
		}
		time.Sleep(20 * time.Millisecond)
	}
}
