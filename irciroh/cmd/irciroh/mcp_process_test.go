//go:build unix

package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// TestMCPProcess runs the real command entry point over stdin and stdout.
func TestMCPProcess(t *testing.T) {
	if os.Getenv("IRCIROH_TEST_MCP") != "1" {
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

// TestMCPSeparateProcess checks framing, tools, resource notifications,
// cancellation, and normal stdin shutdown through the SDK's command transport.
// The parent holds the directory lock as a chat would; the child is a view,
// and no endpoint or public network service is needed.
func TestMCPSeparateProcess(t *testing.T) {
	if testing.Short() {
		t.Skip("subprocess MCP test")
	}
	root := chatDir(t, "2026-01-01T00:00:00Z -!- alice joined #go")
	lock, err := lockChat(root)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, exe, "-test.run=^TestMCPProcess$", "--",
		"mcp", "-dir", root, "-relay=false", "-rendezvous=false")
	cmd.Env = append(os.Environ(), "IRCIROH_TEST_MCP=1")
	stderr, err := os.Create(filepath.Join(t.TempDir(), "stderr"))
	if err != nil {
		t.Fatal(err)
	}
	defer stderr.Close()
	cmd.Stderr = stderr
	updated := make(chan string, 8)
	client := mcp.NewClient(&mcp.Implementation{Name: "process-test", Version: "1"}, &mcp.ClientOptions{
		ResourceUpdatedHandler: func(_ context.Context, req *mcp.ResourceUpdatedNotificationRequest) {
			select {
			case updated <- req.Params.URI:
			default:
			}
		},
	})
	dispatched := make(chan struct{}, 1)
	client.AddSendingMiddleware(func(next mcp.MethodHandler) mcp.MethodHandler {
		return func(ctx context.Context, method string, req mcp.Request) (mcp.Result, error) {
			if params, ok := req.GetParams().(*mcp.CallToolParams); ok && method == "tools/call" {
				if args, ok := params.Arguments.(waitIn); ok && args.Match == "arrived" {
					dispatched <- struct{}{}
				}
			}
			return next(ctx, method, req)
		}
	})
	subscribed := resourceAcknowledgements(client)
	// Leave time for the race runtime's exit delay before sending SIGTERM.
	cs, err := client.Connect(ctx, &mcp.CommandTransport{Command: cmd, TerminateDuration: 3 * time.Second}, nil)
	if err != nil {
		t.Fatal(err)
	}
	closed := false
	t.Cleanup(func() {
		if !closed {
			_ = cs.Close()
		}
		if t.Failed() {
			b, _ := os.ReadFile(stderr.Name())
			t.Logf("mcp stderr: %s", b)
		}
	})
	tools, err := cs.ListTools(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, tool := range tools.Tools {
		if tool.Name == "irc_wait" {
			found = true
		}
	}
	if !found {
		t.Fatal("irc_wait tool missing")
	}
	resources, err := cs.ListResources(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	const uri = "irc:///%23go"
	if len(resources.Resources) != 1 || resources.Resources[0].URI != uri {
		t.Fatalf("resources = %+v, want %s", resources.Resources, uri)
	}
	subscribeResource(t, ctx, cs, subscribed, uri)
	out := call[sendOut](t, cs, "irc_send", sendIn{Target: "#go", Text: "hello\n/KICK bob"})
	if out.Sent != 2 {
		t.Fatalf("sent = %d, want 2", out.Sent)
	}
	b, err := os.ReadFile(filepath.Join(root, "#go", "in"))
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != "hello\n//KICK bob\n" {
		t.Fatalf("queued speech = %q", b)
	}

	// A client deadline must cancel a long wait without losing the session.
	waitCtx, stop := context.WithTimeout(ctx, 200*time.Millisecond)
	_, err = cs.CallTool(waitCtx, &mcp.CallToolParams{Name: "irc_wait", Arguments: waitIn{
		Target: "#go", Match: "not yet", Seconds: 600,
	}})
	stop()
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("cancelled wait = %v, want deadline exceeded", err)
	}
	if _, err := cs.ListResources(ctx, nil); err != nil {
		t.Fatalf("session after cancelled wait: %v", err)
	}

	// Start a non-history wait and confirm it remains pending while another
	// request completes. The bounded pending check is not instrumentation
	// inside the server handler; a match appended too early must fail rather
	// than pass through the history fast path.
	type answer struct {
		result *mcp.CallToolResult
		err    error
	}
	answered := make(chan answer, 1)
	go func() {
		res, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: "irc_wait", Arguments: waitIn{
			Target: "#go", Match: "arrived", Seconds: 10, History: false,
		}})
		answered <- answer{res, err}
	}()
	select {
	case <-dispatched:
	case <-ctx.Done():
		t.Fatal("wait request did not reach client dispatch:", ctx.Err())
	}
	if _, err := cs.ListResources(ctx, nil); err != nil {
		t.Fatalf("session with pending wait: %v", err)
	}
	pending := time.NewTimer(200 * time.Millisecond)
	defer pending.Stop()
	select {
	case a := <-answered:
		t.Fatalf("non-history wait returned before matching append: %+v, %v", a.result, a.err)
	case <-pending.C:
	case <-ctx.Done():
		t.Fatal("pending wait observation:", ctx.Err())
	}
	if err := appendLines(filepath.Join(root, "#go", "out"), []string{
		"@k=" + keyBob + " 2026-01-01T00:00:01Z <bob> arrived",
	}); err != nil {
		t.Fatal(err)
	}
	select {
	case a := <-answered:
		if a.err != nil {
			t.Fatal(a.err)
		}
		if a.result.IsError {
			t.Fatal(text2(a.result))
		}
		b, err := json.Marshal(a.result.StructuredContent)
		if err != nil {
			t.Fatal(err)
		}
		var out waitOut
		if err := json.Unmarshal(b, &out); err != nil {
			t.Fatal(err)
		}
		if !out.Matched || len(out.Lines) != 1 || out.Lines[0].Key != keyBob || out.Lines[0].Text != "arrived" {
			t.Fatalf("wait answer = %+v", out)
		}
	case <-ctx.Done():
		t.Fatal("wait did not return:", ctx.Err())
	}
	select {
	case got := <-updated:
		if got != uri {
			t.Fatalf("updated resource = %s, want %s", got, uri)
		}
	case <-ctx.Done():
		t.Fatal("resource update did not arrive:", ctx.Err())
	}
	read, err := cs.ReadResource(ctx, &mcp.ReadResourceParams{URI: uri})
	if err != nil {
		t.Fatal(err)
	}
	if len(read.Contents) != 1 || !strings.Contains(read.Contents[0].Text, "arrived") {
		t.Fatalf("resource does not contain appended message: %+v", read.Contents)
	}
	if err := cs.Close(); err != nil {
		t.Fatalf("stdio shutdown: %v", err)
	}
	closed = true
	if cmd.ProcessState == nil || !cmd.ProcessState.Success() {
		t.Fatalf("child did not exit normally: %v", cmd.ProcessState)
	}
}
