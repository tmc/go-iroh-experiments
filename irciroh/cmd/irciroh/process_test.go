package main

import (
	"bufio"
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tmc/go-iroh-experiments/irciroh"
)

// TestServeProcess runs the real command entry point in a child process.
func TestServeProcess(t *testing.T) {
	if os.Getenv("IRCIROH_TEST_SERVE") != "1" {
		return
	}
	for i, arg := range os.Args {
		if arg == "--" {
			os.Args = append([]string{"irciroh"}, os.Args[i+1:]...)
			main()
			os.Exit(0)
		}
	}
	t.Fatal("missing command arguments")
}

func startServeProcess(t *testing.T, ctx context.Context) string {
	t.Helper()
	addr, _ := startServeProcessState(t, ctx, t.TempDir())
	return addr
}

// startServeProcessState starts a bridge with reusable durable state. The
// returned stop function kills and reaps it before another bridge opens it.
func startServeProcessState(t *testing.T, ctx context.Context, state string) (string, func()) {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.CommandContext(ctx, exe, "-test.run=^TestServeProcess$", "--",
		"serve", "-listen", "127.0.0.1:0", "-bind", "[::1]:0",
		"-state", state, "-key", filepath.Join(state, "key"),
		"-relay=false", "-rendezvous=false")
	cmd.Env = append(os.Environ(), "IRCIROH_TEST_SERVE=1")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	var once sync.Once
	stop := func() {
		once.Do(func() {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
		})
	}
	t.Cleanup(func() {
		stop()
		if t.Failed() {
			t.Logf("serve stderr: %s", stderr.String())
		}
	})
	address := make(chan string, 1)
	go func() {
		defer close(address)
		s := bufio.NewScanner(stdout)
		for s.Scan() {
			if addr, ok := strings.CutPrefix(s.Text(), "listening for IRC clients on "); ok {
				address <- addr
			}
		}
	}()
	select {
	case addr := <-address:
		if addr == "" {
			t.Fatal("serve exited before listening")
		}
		return addr, stop
	case <-ctx.Done():
		t.Fatal("serve did not start:", ctx.Err())
		return "", stop
	}
}

// TestBridgeSeparateProcesses checks registration, ticket admission, channel
// traffic in both directions, and direct messages across two real commands.
func TestBridgeSeparateProcesses(t *testing.T) {
	if testing.Short() {
		t.Skip("subprocess network test")
	}
	for _, sealed := range []bool{false, true} {
		name := "public"
		if sealed {
			name = "sealed"
		}
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
			defer cancel()
			alice := dialIRC(t, startServeProcess(t, ctx))
			bob := dialIRC(t, startServeProcess(t, ctx))
			alice.register("alice")
			bob.register("bob")
			join := "JOIN #process"
			if sealed {
				join += " seal"
			}
			alice.send(join)
			alice.expect("alice!", "JOIN #process")
			alice.send("TICKET #process")
			line := alice.expect("NOTICE", "irciroh")
			_, params := parseLine(line)
			bob.send("JOIN #process " + params[len(params)-1])
			bob.expect("bob!", "JOIN #process")
			if sealed {
				alice.expect("NICK", "bob")
			} else {
				alice.expect("bob!", "JOIN #process")
			}
			alice.send("PRIVMSG #process :hello from alice")
			bob.expect("alice!", "PRIVMSG #process", "hello from alice")
			bob.send("PRIVMSG #process :hello from bob")
			alice.expect("bob!", "PRIVMSG #process", "hello from bob")
			bob.send("PRIVMSG alice :direct hello")
			alice.expect("bob!", "PRIVMSG alice", "direct hello")
		})
	}
}

// TestBridgeFounderProcessRestart checks that a killed founder retains its
// identity and sealed invite secret, and readmits a still-running member
// whose TLS session cache came from the previous founder process.
func TestBridgeFounderProcessRestart(t *testing.T) {
	if testing.Short() {
		t.Skip("subprocess network test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	state := t.TempDir()
	addr, stop := startServeProcessState(t, ctx, state)
	alice := dialIRC(t, addr)
	alice.register("alice")
	alice.send("JOIN #restart seal")
	alice.expect("alice!", "JOIN #restart")
	before := processTicket(t, alice, "#restart")
	identity, err := os.ReadFile(filepath.Join(state, "key"))
	if err != nil {
		t.Fatal(err)
	}
	bob := dialIRC(t, startServeProcess(t, ctx))
	bob.register("bob")
	bob.send("JOIN #restart " + before.String())
	bob.expect("bob!", "JOIN #restart")
	alice.expect("NICK", "bob")
	bob.send("PRIVMSG #restart :before founder restart")
	alice.expect("bob!", "PRIVMSG #restart", "before founder restart")
	// Exercise a repeat invitation before restart, retaining the same
	// member process and its asynchronous TLS session cache.
	bob.send("PART #restart")
	bob.expect("bob!", "PART #restart")
	bob.send("JOIN #restart " + before.String())
	bob.expect("bob!", "JOIN #restart")
	bob.send("PRIVMSG #restart :repeat invitation before restart")
	alice.expect("bob!", "PRIVMSG #restart", "repeat invitation before restart")
	stop()

	addr, _ = startServeProcessState(t, ctx, state)
	alice = dialIRC(t, addr)
	alice.register("alice")
	// A bare JOIN after restart must restore the seal, not join the public
	// channel of the same name.
	alice.send("JOIN #restart")
	alice.expect(" 353 ", "#restart", "@alice")
	after := processTicket(t, alice, "#restart")
	if !after.Sealed() || before.Founder != after.Founder || !bytes.Equal(before.Secret, after.Secret) {
		t.Fatal("restart changed the sealed channel identity or invite secret")
	}
	got, err := os.ReadFile(filepath.Join(state, "key"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, identity) {
		t.Fatal("restart changed the endpoint key")
	}

	// Refresh only transport addresses in the previously issued invitation.
	// The founder and secret must still be valid after a process restart.
	before.Peers = after.Peers
	bob.send("PART #restart")
	bob.expect("bob!", "PART #restart")
	bob.send("JOIN #restart " + before.String())
	bob.expect("bob!", "JOIN #restart")
	alice.expect("NICK", "bob")
	alice.send("PRIVMSG #restart :new group after restart")
	bob.expect("alice!", "PRIVMSG #restart", "new group after restart")
	bob.send("PRIVMSG #restart :member can reply")
	alice.expect("bob!", "PRIVMSG #restart", "member can reply")
}

func processTicket(t *testing.T, client *ircClient, channel string) irciroh.Ticket {
	t.Helper()
	client.send("TICKET " + channel)
	line := client.expect("NOTICE", "irciroh")
	_, params := parseLine(line)
	ticket, err := irciroh.ParseTicket(params[len(params)-1])
	if err != nil {
		t.Fatal(err)
	}
	return ticket
}

// TestBridgeMemberProcessRestart checks that a member's persisted identity
// can rejoin after a crash and exchange messages in both channel modes.
func TestBridgeMemberProcessRestart(t *testing.T) {
	if testing.Short() {
		t.Skip("subprocess network test")
	}
	for _, mode := range []string{"public", "sealed"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
			defer cancel()
			alice := dialIRC(t, startServeProcess(t, ctx))
			alice.register("alice")
			join := "JOIN #restart"
			if mode == "sealed" {
				join += " seal"
			}
			alice.send(join)
			alice.expect("alice!", "JOIN #restart")
			ticket := processTicket(t, alice, "#restart")
			state := t.TempDir()
			addr, stop := startServeProcessState(t, ctx, state)
			bob := dialIRC(t, addr)
			bob.register("bob")
			bob.send("JOIN #restart " + ticket.String())
			bob.expect("bob!", "JOIN #restart")
			if mode == "sealed" {
				alice.expect("NICK", "bob")
			} else {
				alice.expect("bob!", "JOIN #restart")
			}
			bob.send("PRIVMSG #restart :before crash")
			alice.expect("bob!", "PRIVMSG #restart", "before crash")
			identity, err := os.ReadFile(filepath.Join(state, "key"))
			if err != nil {
				t.Fatal(err)
			}
			stop()

			addr, _ = startServeProcessState(t, ctx, state)
			bob = dialIRC(t, addr)
			bob.register("bob")
			got, err := os.ReadFile(filepath.Join(state, "key"))
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, identity) {
				t.Fatal("member restart changed the endpoint key")
			}
			bob.send("JOIN #restart " + ticket.String())
			bob.expect("bob!", "JOIN #restart")
			bob.send("PRIVMSG #restart :after crash")
			alice.expect("bob!", "PRIVMSG #restart", "after crash")
			alice.send("PRIVMSG #restart :reply after crash")
			bob.expect("alice!", "PRIVMSG #restart", "reply after crash")
		})
	}
}
