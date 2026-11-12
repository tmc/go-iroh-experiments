package main

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

func startChatProcess(t *testing.T, ctx context.Context, server, dir string) func() {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	// TestServeProcess dispatches main with the arguments after --, so this
	// executes the actual chat command in a separate operating system process.
	cmd := exec.CommandContext(ctx, exe, "-test.run=^TestServeProcess$", "--",
		"chat", "-server", server, "-dir", dir, "-nick", "alice", "-join", "#process")
	cmd.Env = append(os.Environ(), "IRCIROH_TEST_SERVE=1")
	var output bytes.Buffer
	cmd.Stdout = &output
	cmd.Stderr = &output
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
			t.Logf("chat output: %s", output.String())
		}
	})
	return stop
}

// TestChatSeparateProcesses exercises the file interface through real serve
// and chat commands, including the saved queue offset after a chat crash.
func TestChatSeparateProcesses(t *testing.T) {
	if testing.Short() {
		t.Skip("subprocess network test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	server := startServeProcess(t, ctx)
	dir := t.TempDir()
	stop := startChatProcess(t, ctx, server, dir)
	out := filepath.Join(dir, "#process", "out")
	in := filepath.Join(dir, "#process", "in")
	waitFor(t, out, "alice joined")
	self, err := chatKey(dir)
	if err != nil || !hexKey.MatchString(self) {
		t.Fatalf("chat identity = %q, %v", self, err)
	}
	if !chatting(dir) {
		t.Fatal("child chat does not hold the directory lock")
	}

	appendLine(t, in, "/TICKET #process")
	fields := strings.Fields(waitFor(t, filepath.Join(dir, "out"), "-"+serverName+"- irciroh"))
	bob := dialIRC(t, startServeProcess(t, ctx))
	bob.register("bob")
	bob.send("JOIN #process " + fields[len(fields)-1])
	bob.expect("bob!", "JOIN #process")
	waitFor(t, out, "bob joined")
	appendLine(t, in, "already sent before crash")
	bob.expect("alice!", "PRIVMSG #process", "already sent before crash")
	bob.send("PRIVMSG #process :inbound before crash")
	line := waitFor(t, out, "inbound before crash")
	nick, peer, text, ok := speech(line)
	if !ok || nick != "bob" || !hexKey.MatchString(peer) || peer == self || text != "inbound before crash" {
		t.Fatalf("inbound log lacks remote identity: %q", line)
	}
	info, err := os.Stat(in)
	if err != nil {
		t.Fatal(err)
	}
	waitFor(t, in+".sent", strconv.FormatInt(info.Size(), 10))
	stop()
	if chatting(dir) {
		t.Fatal("killed chat retained the directory lock")
	}
	before, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}

	// The saved offset separates an already sent line from one appended
	// while no chat process owns the directory.
	appendLine(t, in, "queued while chat stopped")
	startChatProcess(t, ctx, server, dir)
	queued := 0
	readUntil := func(want string) {
		t.Helper()
		for {
			line, err := bob.r.ReadString('\n')
			if err != nil {
				t.Fatalf("waiting for %q: %v", want, err)
			}
			t.Logf("restart IRC: %s", strings.TrimSpace(line))
			if strings.Contains(line, "PRIVMSG #process :already sent before crash") {
				t.Fatalf("chat replayed a sent queue entry: %q", line)
			}
			if strings.Contains(line, "PRIVMSG #process :queued while chat stopped") {
				queued++
				if queued > 1 {
					t.Fatalf("chat sent the offline queue entry twice: %q", line)
				}
			}
			if strings.Contains(line, want) {
				return
			}
		}
	}
	readUntil("PRIVMSG #process :queued while chat stopped")
	bob.send("PRIVMSG #process :inbound after restart")
	line = waitFor(t, out, "inbound after restart")
	nick, gotPeer, text, ok := speech(line)
	if !ok || nick != "bob" || gotPeer != peer || text != "inbound after restart" {
		t.Fatalf("restart lost the incoming peer identity: %q", line)
	}
	// Continue checking through the return exchange and a later queued IRC
	// PING. Its logged PONG orders the chat's earlier writes to its bridge;
	// the second PONG drains responses already queued on the peer socket.
	// Neither barrier orders arbitrary future gossip delivery, so this is
	// a bounded replay check rather than an indefinite exactly-once claim.
	appendLine(t, in, "/PING :chat-outbox-barrier")
	waitFor(t, filepath.Join(dir, "out"), "PONG irciroh :chat-outbox-barrier")
	bob.send("PING :chat-restart-barrier")
	readUntil("PONG irciroh :chat-restart-barrier")
	after, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(after, before) {
		t.Fatal("chat restart replaced the existing conversation log")
	}
	gotSelf, err := chatKey(dir)
	if err != nil || gotSelf != self {
		t.Fatalf("restart chat identity = %q, %v; want %q", gotSelf, err, self)
	}
}
