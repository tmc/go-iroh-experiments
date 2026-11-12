//go:build unix

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type chatCommand struct {
	cmd    *exec.Cmd
	done   chan struct{}
	err    error
	output bytes.Buffer
}

// startJoinedChatProcess accepts a ticket in the ordinary chat -join syntax.
// Wait is owned by one goroutine, so tests may observe natural command exit
// as well as kill it without racing cleanup or consuming its exit status.
func startJoinedChatProcess(t *testing.T, ctx context.Context, server, dir, join string) *chatCommand {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	p := &chatCommand{done: make(chan struct{})}
	p.cmd = exec.CommandContext(ctx, exe, "-test.run=^TestServeProcess$", "--",
		"chat", "-server", server, "-dir", dir, "-nick", "bob", "-join", join)
	p.cmd.Env = append(os.Environ(), "IRCIROH_TEST_SERVE=1")
	p.cmd.Stdout, p.cmd.Stderr = &p.output, &p.output
	if err := p.cmd.Start(); err != nil {
		t.Fatal(err)
	}
	go func() {
		p.err = p.cmd.Wait()
		close(p.done)
	}()
	t.Cleanup(func() {
		_ = p.cmd.Process.Kill()
		select {
		case <-p.done:
			if t.Failed() {
				t.Logf("chat command output: %s", p.output.String())
			}
		case <-time.After(5 * time.Second):
			t.Error("chat command did not exit during cleanup")
		}
	})
	return p
}

func compositionMCP(t *testing.T, ctx context.Context, dir string) *mcp.ClientSession {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	stderr, err := os.Create(filepath.Join(t.TempDir(), "mcp.stderr"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = stderr.Close() })
	cmd := exec.CommandContext(ctx, exe, "-test.run=^TestMCPProcess$", "--", "mcp",
		"-dir", dir, "-state", t.TempDir(), "-bind", "[::1]:0", "-relay=false", "-rendezvous=false")
	cmd.Env = append(os.Environ(), "IRCIROH_TEST_MCP=1")
	cmd.Stderr = stderr
	client := mcp.NewClient(&mcp.Implementation{Name: "composition-test", Version: "1"}, nil)
	cs, err := client.Connect(ctx, &mcp.CommandTransport{Command: cmd, TerminateDuration: 3 * time.Second}, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = cs.Close()
		if t.Failed() {
			b, _ := os.ReadFile(stderr.Name())
			t.Logf("composition MCP stderr: %s", b)
		}
	})
	return cs
}

func compositionSend(t *testing.T, ctx context.Context, cs *mcp.ClientSession, message string) {
	t.Helper()
	res, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name: "irc_send", Arguments: sendIn{Target: "#flow", Text: message},
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.IsError {
		t.Fatal(text2(res))
	}
	b, err := json.Marshal(res.StructuredContent)
	if err != nil {
		t.Fatal(err)
	}
	var sent sendOut
	if err := json.Unmarshal(b, &sent); err != nil {
		t.Fatal(err)
	}
	if sent.Sent != 1 || sent.Queued {
		t.Fatalf("MCP send = %+v, want one line with chat attached", sent)
	}
}

// TestServeChatMCPProcesses checks the supported command composition against
// a live remote bridge. MCP queues actual outgoing network traffic, and its
// resource reports an incoming network message with the remote endpoint key.
func TestServeChatMCPProcesses(t *testing.T) {
	if testing.Short() {
		t.Skip("subprocess network test")
	}
	for _, mode := range []string{"public", "sealed"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
			defer cancel()
			alice := dialIRC(t, startServeProcess(t, ctx))
			alice.register("alice")
			join := "JOIN #flow"
			if mode == "sealed" {
				join += " seal"
			}
			alice.send(join)
			alice.expect("alice!", "JOIN #flow")
			ticket := processTicket(t, alice, "#flow")
			dir := t.TempDir()
			startJoinedChatProcess(t, ctx, startServeProcess(t, ctx), dir, "#flow "+ticket.String())
			out := filepath.Join(dir, "#flow", "out")
			waitFor(t, out, "bob joined")
			if mode == "sealed" {
				alice.expect("NICK", "bob")
			} else {
				alice.expect("bob!", "JOIN #flow")
			}
			cs := compositionMCP(t, ctx, dir)
			compositionSend(t, ctx, cs, "MCP through chat to remote bridge")
			alice.expect("bob!", "PRIVMSG #flow", "MCP through chat to remote bridge")
			alice.send("PRIVMSG #flow :remote bridge through chat to MCP")
			line := waitFor(t, out, "remote bridge through chat to MCP")
			nick, peer, _, ok := speech(line)
			if !ok || nick != "alice" || peer != ticket.Peers[0].ID.String() {
				t.Fatalf("incoming network log identity = %q, want %s: %q", peer, ticket.Peers[0].ID, line)
			}
			resource, err := cs.ReadResource(ctx, &mcp.ReadResourceParams{URI: "irc:///%23flow"})
			if err != nil {
				t.Fatal(err)
			}
			if len(resource.Contents) != 1 {
				t.Fatalf("resource contents = %d, want 1", len(resource.Contents))
			}
			var lines []Line
			if err := json.Unmarshal([]byte(resource.Contents[0].Text), &lines); err != nil {
				t.Fatal(err)
			}
			found := false
			for _, line := range lines {
				if line.Text == "remote bridge through chat to MCP" && line.From == "alice" && line.Key == peer {
					found = true
				}
			}
			if !found {
				t.Fatalf("MCP resource lacks authenticated incoming network message: %+v", lines)
			}
		})
	}
}

// TestSealedChatProcessRecovery checks that an explicit chat restart keeps
// the sealed ticket, directory identity and queue offset. On bridge EOF chat
// exits normally and releases its directory; it does not reconnect itself.
func TestSealedChatProcessRecovery(t *testing.T) {
	if testing.Short() {
		t.Skip("subprocess network test")
	}
	for _, failure := range []string{"chat crash", "bridge outage"} {
		t.Run(failure, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
			defer cancel()
			alice := dialIRC(t, startServeProcess(t, ctx))
			alice.register("alice")
			alice.send("JOIN #flow seal")
			alice.expect("alice!", "JOIN #flow")
			ticket := processTicket(t, alice, "#flow")
			state := t.TempDir()
			addr, stopBridge := startServeProcessState(t, ctx, state)
			dir := t.TempDir()
			chat := startJoinedChatProcess(t, ctx, addr, dir, "#flow "+ticket.String())
			out, in := filepath.Join(dir, "#flow", "out"), filepath.Join(dir, "#flow", "in")
			waitFor(t, out, "bob joined")
			alice.expect("NICK", "bob")
			self, err := chatKey(dir)
			if err != nil || !hexKey.MatchString(self) {
				t.Fatalf("sealed chat identity = %q, %v", self, err)
			}
			if !chatting(dir) {
				t.Fatal("sealed chat does not own its directory")
			}
			appendLine(t, in, "already delivered sealed speech")
			alice.expect("bob!", "PRIVMSG #flow", "already delivered sealed speech")
			if failure == "chat crash" {
				_ = chat.cmd.Process.Kill()
			} else {
				stopBridge()
			}
			select {
			case <-chat.done:
			case <-ctx.Done():
				t.Fatal("chat did not exit:", ctx.Err())
			}
			if failure == "bridge outage" && chat.err != nil {
				t.Fatalf("chat exit after bridge EOF = %v, want normal exit", chat.err)
			}
			if chatting(dir) {
				t.Fatal("exited chat retained the directory lock")
			}
			before, err := os.ReadFile(out)
			if err != nil {
				t.Fatal(err)
			}
			appendLine(t, in, "sealed speech queued while stopped")
			if failure == "bridge outage" {
				addr, _ = startServeProcessState(t, ctx, state)
			}
			startJoinedChatProcess(t, ctx, addr, dir, "#flow "+ticket.String())
			queued := 0
			readUntil := func(want string) {
				t.Helper()
				for {
					line, err := alice.r.ReadString('\n')
					if err != nil {
						t.Fatalf("waiting for %q: %v", want, err)
					}
					if strings.Contains(line, "PRIVMSG #flow :already delivered sealed speech") {
						t.Fatalf("chat replayed previously delivered sealed speech: %q", line)
					}
					if strings.Contains(line, "PRIVMSG #flow :sealed speech queued while stopped") {
						queued++
						if queued > 1 {
							t.Fatalf("chat duplicated offline sealed speech: %q", line)
						}
					}
					if strings.Contains(line, want) {
						return
					}
				}
			}
			readUntil("PRIVMSG #flow :sealed speech queued while stopped")
			if !chatting(dir) {
				t.Fatal("restarted sealed chat does not own its directory")
			}
			alice.send("PRIVMSG #flow :inbound after sealed chat restart")
			waitFor(t, out, "inbound after sealed chat restart")
			appendLine(t, in, "/PING :sealed-chat-queue-barrier")
			waitFor(t, filepath.Join(dir, "out"), "PONG irciroh :sealed-chat-queue-barrier")
			alice.send("PING :sealed-chat-peer-barrier")
			readUntil("PONG irciroh :sealed-chat-peer-barrier")
			after, err := os.ReadFile(out)
			if err != nil || !bytes.HasPrefix(after, before) {
				t.Fatalf("sealed log was replaced on restart: %v", err)
			}
			got, err := chatKey(dir)
			if err != nil || got != self {
				t.Fatalf("sealed chat identity after restart = %q, %v; want %q", got, err, self)
			}
		})
	}
}
