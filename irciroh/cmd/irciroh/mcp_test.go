package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/tmc/go-iroh-experiments/irciroh"
	"github.com/tmc/go-iroh/key"
)

// session starts a server on a directory and connects a client to it,
// the way an editor would, and hands back the client's side.
func session(t *testing.T, root string) *mcp.ClientSession {
	t.Helper()
	ctx := context.Background()
	server, client := mcp.NewInMemoryTransports()
	m := newMCPServer(root)
	serving, err := m.s.Connect(ctx, server, nil)
	if err != nil {
		t.Fatal(err)
	}
	watch, stop := context.WithCancel(ctx)
	go m.watch(watch)
	c := mcp.NewClient(&mcp.Implementation{Name: "test", Version: "1"}, nil)
	cs, err := c.Connect(ctx, client, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		stop()
		cs.Close()
		serving.Close()
	})
	return cs
}

// call runs a tool and decodes its structured output, which is the
// half of the answer a program reads.
func call[T any](t *testing.T, cs *mcp.ClientSession, name string, args any) T {
	t.Helper()
	res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: name, Arguments: args})
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	if res.IsError {
		t.Fatalf("%s: %s", name, text2(res))
	}
	var out T
	b, err := json.Marshal(res.StructuredContent)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatalf("%s: structured output %s: %v", name, b, err)
	}
	return out
}

func text2(res *mcp.CallToolResult) string {
	var b strings.Builder
	for _, c := range res.Content {
		if tc, ok := c.(*mcp.TextContent); ok {
			b.WriteString(tc.Text)
		}
	}
	return b.String()
}

// Endpoint keys, as the log records them: in full. keyTMC and keyNotTMC
// agree in their first six hex digits, because twenty-four bits of a
// key is minutes of grinding - so a test that tells two speakers apart
// by what is printed would pass while the thing it checks is broken.
var (
	keyBob    = "b0b0b0" + strings.Repeat("ab", 29)
	keyTMC    = "7fa31c" + strings.Repeat("11", 29)
	keyNotTMC = "7fa31c" + strings.Repeat("22", 29)
	keyAlice  = "d4d4d4" + strings.Repeat("cd", 29)
)

// chatDir builds the directory a chat would have left behind.
func chatDir(t *testing.T, lines ...string) string {
	t.Helper()
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "#go"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "#go", "out"), []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return root
}

// TestMCPTools checks that the server offers what it says it does,
// with the schemas the SDK derives from the handlers' arguments. A
// client that cannot see an input schema cannot call a tool.
func TestMCPTools(t *testing.T) {
	cs := session(t, chatDir(t, "2026-01-01T00:00:00Z -!- alice joined #go"))
	tools, err := cs.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{
		"irc_channels": false, "irc_read": false, "irc_send": false,
		"irc_wait": false, "irc_join": false, "irc_ticket": false,
		"irc_whoami": false,
	}
	for _, tool := range tools.Tools {
		if _, ok := want[tool.Name]; !ok {
			t.Errorf("unexpected tool %s", tool.Name)
			continue
		}
		want[tool.Name] = true
		if tool.Description == "" {
			t.Errorf("%s has no description", tool.Name)
		}
		if tool.InputSchema == nil {
			t.Errorf("%s has no input schema", tool.Name)
		}
		if tool.OutputSchema == nil {
			t.Errorf("%s has no output schema", tool.Name)
		}
	}
	for name, found := range want {
		if !found {
			t.Errorf("%s is missing", name)
		}
	}
}

// TestMCPRead checks that a read answers with the lines taken apart -
// who spoke, when, and what kind of line it was - as well as with the
// log itself.
func TestMCPRead(t *testing.T) {
	root := chatDir(t,
		"2026-01-01T00:00:00Z -!- alice joined #go",
		"@k="+keyBob+" 2026-01-01T00:00:01Z <bob> the eagle has landed",
		"@k="+keyTMC+" 2026-01-01T00:00:02Z <tmc> it is me",
		"@k="+keyNotTMC+" 2026-01-01T00:00:03Z <tmc> no, it is me",
		"@t=1767225604;k="+keyAlice+" 2026-01-01T00:00:04Z -alice- heads up",
		"2026-01-01T00:00:05Z -irciroh- a notice",
	)
	cs := session(t, root)

	got := call[linesOut](t, cs, "irc_read", readIn{Target: "#go"})
	if len(got.Lines) != 6 {
		t.Fatalf("read %d lines, want 6", len(got.Lines))
	}
	// Nothing is pinned in this directory, so every signed line is
	// unknown and the unsigned ones are unattributed. That is the
	// ordinary state of a new directory and it is a verdict, not a
	// missing answer - which is why the field has no omitempty.
	want := []Line{
		{Time: "2026-01-01T00:00:00Z", Target: "#go", Kind: "event", Verdict: "unattributed", Text: "alice joined #go"},
		{Time: "2026-01-01T00:00:01Z", Target: "#go", Kind: "message", From: "bob", Key: keyBob, Verdict: "unknown", Text: "the eagle has landed"},
		{Time: "2026-01-01T00:00:02Z", Target: "#go", Kind: "message", From: "tmc", Key: keyTMC, Verdict: "unknown", Text: "it is me"},
		{Time: "2026-01-01T00:00:03Z", Target: "#go", Kind: "message", From: "tmc", Key: keyNotTMC, Verdict: "unknown", Text: "no, it is me"},
		{Time: "2026-01-01T00:00:04Z", Target: "#go", Kind: "notice", From: "alice", Key: keyAlice, Verdict: "unknown", Text: "heads up"},
		{Time: "2026-01-01T00:00:05Z", Target: "#go", Kind: "notice", From: "irciroh", Verdict: "unattributed", Text: "a notice"},
	}
	for i, w := range want {
		if got.Lines[i] != w {
			t.Errorf("line %d = %+v, want %+v", i, got.Lines[i], w)
		}
	}

	// Two endpoints claiming the same nick is the whole reason the key
	// is recorded: the nicks agree and the answer must still tell them
	// apart.
	if a, b := got.Lines[2], got.Lines[3]; a.From != b.From {
		t.Fatalf("the two claims to %q were not both parsed as it: %+v, %+v", "tmc", a, b)
	} else if a.Key == b.Key {
		t.Errorf("two endpoints claiming %q came back identical: %+v, %+v", a.From, a, b)
	}

	// The two halves of the answer say different amounts on purpose. The
	// text is read by a person and shows six hex digits, which the
	// second tmc has ground to match the first; the structured half
	// holds the whole key, which is what a comparison must use. A change
	// that collapses the two - a full key in the text, or a short one in
	// the record - fails here, and should.
	shown, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: "irc_read", Arguments: readIn{Target: "#go"}})
	if err != nil {
		t.Fatal(err)
	}
	said := text2(shown)
	for _, want := range []string{
		"<bob[b0b0b0]> the eagle has landed",
		"<tmc[7fa31c]> it is me",
		"<tmc[7fa31c]> no, it is me",
		"-alice[d4d4d4]- heads up",
		"-irciroh- a notice",
	} {
		if !strings.Contains(said, want) {
			t.Errorf("the text of the answer does not hold %q:\n%s", want, said)
		}
	}
	if strings.Contains(said, keyTMC) {
		t.Errorf("the text of the answer spends a whole key on a line:\n%s", said)
	}
	if got.Lines[2].Key == shortKey(got.Lines[2].Key) {
		t.Errorf("the record holds only as much key as is printed: %q", got.Lines[2].Key)
	}

	// A match narrows it, and a limit keeps the most recent.
	if got := call[linesOut](t, cs, "irc_read", readIn{Target: "#go", Match: "eagle"}); len(got.Lines) != 1 {
		t.Errorf("match returned %d lines, want 1", len(got.Lines))
	}
	if got := call[linesOut](t, cs, "irc_read", readIn{Target: "#go", Limit: 1}); len(got.Lines) != 1 || got.Lines[0].From != "irciroh" {
		t.Errorf("limit returned %+v, want the last line", got.Lines)
	}

	// A target that is not a conversation is an error the caller can
	// read, not a panic and not an empty answer.
	res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: "irc_read", Arguments: readIn{Target: "#nope"}})
	if err != nil {
		t.Fatal(err)
	}
	if !res.IsError {
		t.Error("reading a channel this node is not in was not an error")
	}
}

// TestMCPSendIsSpeech checks that what a model writes stays speech. A
// leading slash is a command in an in file, and a model that has been
// talked into writing one must not be handed the command set of IRC.
func TestMCPSendIsSpeech(t *testing.T) {
	root := chatDir(t, "2026-01-01T00:00:00Z -!- alice joined #go")
	cs := session(t, root)
	out := call[sendOut](t, cs, "irc_send", sendIn{Target: "#go", Text: "hello\n/KICK bob\n"})
	if out.Sent != 2 {
		t.Errorf("sent %d lines, want 2", out.Sent)
	}
	if !out.Queued {
		t.Error("no chat is attached, so the lines are queued; the tool said otherwise")
	}
	b, err := os.ReadFile(filepath.Join(root, "#go", "in"))
	if err != nil {
		t.Fatal(err)
	}
	if got, want := string(b), "hello\n//KICK bob\n"; got != want {
		t.Errorf("in file = %q, want %q", got, want)
	}
}

// TestMCPWaitReturnsTheExchange checks that waiting hands back
// everything said while it waited, not only the line that matched: a
// caller that was away wants what it missed.
//
// The lines are in the log before the wait starts and history is asked
// for, so what is returned does not depend on which of the two came
// first.
func TestMCPWaitReturnsTheExchange(t *testing.T) {
	root := chatDir(t, "2026-01-01T00:00:00Z -!- alice joined #go")
	cs := session(t, root)
	appendLines(filepath.Join(root, "#go", "out"), []string{
		"@k=" + keyBob + " 2026-01-01T00:00:01Z <bob> still here?",
		"@k=" + keyBob + " 2026-01-01T00:00:02Z <bob> the eagle has landed",
		"@k=" + keyBob + " 2026-01-01T00:00:03Z <bob> over",
	})
	out := call[waitOut](t, cs, "irc_wait", waitIn{Target: "#go", Match: "eagle", Seconds: 10, History: true})
	if !out.Matched {
		t.Fatal("wait did not match a line that was said")
	}
	if len(out.Lines) != 3 {
		t.Fatalf("wait returned %d lines, want the 3 up to the match: %+v", len(out.Lines), out.Lines)
	}
	if out.Lines[1].Text != "still here?" {
		t.Errorf("wait dropped what was said before the match: %+v", out.Lines[1])
	}
	if out.Lines[1].Key != keyBob {
		t.Errorf("wait lost the key of who was speaking: %+v", out.Lines[1])
	}

	// Without history, what is already in the log is not waited for.
	if out := call[waitOut](t, cs, "irc_wait", waitIn{Target: "#go", Match: "eagle", Seconds: 1}); out.Matched {
		t.Errorf("wait without history matched a line already logged: %+v", out.Lines)
	}

	// Nothing said is not an error; it is an answer with nothing in it.
	out = call[waitOut](t, cs, "irc_wait", waitIn{Target: "#go", Match: "nobody says this", Seconds: 1})
	if out.Matched {
		t.Error("wait matched a line nobody said")
	}
}

// TestMCPConversationsAreResources checks the half of the server that
// streams: a conversation is a resource, a client can subscribe to it,
// and the server says so when the log grows.
func TestMCPConversationsAreResources(t *testing.T) {
	for _, version := range []string{"2025-11-25", "2026-07-28"} {
		t.Run(version, func(t *testing.T) {
			testMCPConversationsAreResources(t, version)
		})
	}
}

func testMCPConversationsAreResources(t *testing.T, version string) {
	root := chatDir(t, "2026-01-01T00:00:00Z -!- alice joined #go")
	ctx := context.Background()

	updated := make(chan string, 8)
	appeared := make(chan struct{}, 8)
	server, client := mcp.NewInMemoryTransports()
	m := newMCPServer(root)
	serving, err := m.s.Connect(ctx, server, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer serving.Close()
	watch, stop := context.WithCancel(ctx)
	defer stop()
	go m.watch(watch)
	c := mcp.NewClient(&mcp.Implementation{Name: "test", Version: "1"}, &mcp.ClientOptions{
		ResourceUpdatedHandler: func(_ context.Context, req *mcp.ResourceUpdatedNotificationRequest) {
			updated <- req.Params.URI
		},
		ResourceListChangedHandler: func(context.Context, *mcp.ResourceListChangedRequest) {
			appeared <- struct{}{}
		},
	})
	subscribed := resourceAcknowledgements(c)
	cs, err := c.Connect(ctx, client, &mcp.ClientSessionOptions{ProtocolVersion: version})
	if err != nil {
		t.Fatal(err)
	}
	defer cs.Close()

	// Connect also starts the modern list-change subscription asynchronously.
	if cs.InitializeResult().ProtocolVersion >= "2026-07-28" {
		select {
		case uri := <-subscribed:
			if uri != "" {
				t.Fatalf("list subscription acknowledgement = %q", uri)
			}
		case <-time.After(10 * time.Second):
			t.Fatal("resource list subscription was not acknowledged")
		}
	}

	list, err := cs.ListResources(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(list.Resources) != 1 || list.Resources[0].URI != "irc:///%23go" {
		t.Fatalf("resources = %+v, want one named irc:///%%23go", list.Resources)
	}

	read, err := cs.ReadResource(ctx, &mcp.ReadResourceParams{URI: "irc:///%23go"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(read.Contents[0].Text, "alice joined") {
		t.Errorf("resource does not hold the log: %s", read.Contents[0].Text)
	}

	// With the current protocol Subscribe starts a background listen request;
	// its return is not a server-side registration barrier. Wait for the
	// acknowledgement before changing a log the watcher can consume at once.
	subscribeResource(t, ctx, cs, subscribed, "irc:///%23go")
	if err := appendLines(filepath.Join(root, "#go", "out"), []string{"2026-01-01T00:00:01Z <bob> anyone there?"}); err != nil {
		t.Fatal(err)
	}
	select {
	case uri := <-updated:
		if uri != "irc:///%23go" {
			t.Errorf("update named %s", uri)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("a subscriber was not told the conversation grew")
	}

	// A conversation that appears while the client is connected is
	// announced too, so an agent learns about a channel it was invited
	// to without asking.
	if err := os.MkdirAll(filepath.Join(root, "#rust"), 0o700); err != nil {
		t.Fatal(err)
	}
	select {
	case <-appeared:
	case <-time.After(10 * time.Second):
		t.Fatal("a new conversation was not announced")
	}
}

// resourceAcknowledgements records readiness for the current MCP protocol.
// An empty URI marks a list-change subscription. Install before connecting.
func resourceAcknowledgements(c *mcp.Client) <-chan string {
	ready := make(chan string, 8)
	c.AddReceivingMiddleware(func(next mcp.MethodHandler) mcp.MethodHandler {
		return func(ctx context.Context, method string, req mcp.Request) (mcp.Result, error) {
			result, err := next(ctx, method, req)
			if err == nil && method == "notifications/subscriptions/acknowledged" {
				if params, ok := req.GetParams().(*mcp.SubscriptionsAcknowledgedParams); ok {
					if params.Notifications.ResourcesListChanged {
						select {
						case ready <- "":
						case <-ctx.Done():
						}
					}
					for _, uri := range params.Notifications.ResourceSubscriptions {
						select {
						case ready <- uri:
						case <-ctx.Done():
						}
					}
				}
			}
			return result, err
		}
	})
	return ready
}

func subscribeResource(t *testing.T, ctx context.Context, cs *mcp.ClientSession, ready <-chan string, uri string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err := cs.Subscribe(ctx, &mcp.SubscribeParams{URI: uri}); err != nil {
		t.Fatal(err)
	}
	// Legacy Subscribe waits for the server's registration response itself.
	if cs.InitializeResult().ProtocolVersion < "2026-07-28" {
		return
	}
	select {
	case got := <-ready:
		if got != uri {
			t.Fatalf("acknowledged resource = %s, want %s", got, uri)
		}
	case <-ctx.Done():
		t.Fatal("resource subscription was not acknowledged:", ctx.Err())
	}
}

// TestOKTarget checks the one argument that reaches the filesystem
// before it reaches the network, and that comes from a model.
func TestOKTarget(t *testing.T) {
	for _, tt := range []struct {
		target string
		ok     bool
	}{
		{"#go", true},
		{"alice", true},
		{"", false},
		{"#go #rust", false},
		{"#go,#rust", false},
		{"#go\r\nQUIT", false},
		{"../etc", false},
		{"..", false},
		{".", false},
		{"a/b", false},
		{`a\b`, false},
	} {
		if err := okTarget(tt.target); (err == nil) != tt.ok {
			t.Errorf("okTarget(%q) = %v, want ok=%v", tt.target, err, tt.ok)
		}
	}
}

// TestURITarget checks that a channel survives the round trip through
// a URI, where its leading # would otherwise be a fragment.
func TestURITarget(t *testing.T) {
	for _, target := range []string{"#go", "#go-nuts", "alice"} {
		got, err := uriTarget(targetURI(target))
		if err != nil || got != target {
			t.Errorf("round trip of %q = %q, %v", target, got, err)
		}
	}
	if _, err := uriTarget("irc:///..%2fetc"); err == nil {
		t.Error("a URI naming a path was accepted as a conversation")
	}
	if _, err := uriTarget("file:///etc/passwd"); err == nil {
		t.Error("a URI of another scheme was accepted as a conversation")
	}
}

// TestMCPParseLogTags checks the one step the tag prefix added to
// parsing, at its edges: a tag block that does not carry a key, one
// that carries it among others, and a line with no tag block at all,
// which is every line the log held before keys were recorded.
func TestMCPParseLogTags(t *testing.T) {
	for _, tt := range []struct {
		name string
		line string
		want Line
	}{
		{
			"key",
			"@k=" + keyBob + " 2026-01-01T00:00:01Z <bob> hi",
			Line{Time: "2026-01-01T00:00:01Z", Target: "#go", Kind: "message", From: "bob", Key: keyBob, Text: "hi"},
		},
		{
			"tagged but no key",
			"@t=1767225601 2026-01-01T00:00:01Z <bob> hi",
			Line{Time: "2026-01-01T00:00:01Z", Target: "#go", Kind: "message", From: "bob", Text: "hi"},
		},
		{
			"key among other tags",
			"@t=1767225601;k=" + keyBob + ";z=2 2026-01-01T00:00:01Z <bob> hi",
			Line{Time: "2026-01-01T00:00:01Z", Target: "#go", Kind: "message", From: "bob", Key: keyBob, Text: "hi"},
		},
		{
			"empty key",
			"@k= 2026-01-01T00:00:01Z <bob> hi",
			Line{Time: "2026-01-01T00:00:01Z", Target: "#go", Kind: "message", From: "bob", Text: "hi"},
		},
		{
			"no tags at all",
			"2026-01-01T00:00:01Z <bob> hi",
			Line{Time: "2026-01-01T00:00:01Z", Target: "#go", Kind: "message", From: "bob", Text: "hi"},
		},
		{
			"an event can be tagged too",
			"@k=" + keyBob + " 2026-01-01T00:00:01Z -!- bob joined #go",
			Line{Time: "2026-01-01T00:00:01Z", Target: "#go", Kind: "event", Key: keyBob, Text: "bob joined #go"},
		},
		{
			// Nothing follows the tags, so there is no line under them;
			// it is handed back whole rather than guessed at.
			"tags and nothing else",
			"@k=" + keyBob,
			Line{Target: "#go", Kind: "line", Text: "@k=" + keyBob},
		},
	} {
		if got := parseLog("#go", tt.line); got != tt.want {
			t.Errorf("%s: parseLog(%q) = %+v, want %+v", tt.name, tt.line, got, tt.want)
		}
	}
}

// callRaw calls a tool and returns the whole answer, for the tests that
// are about the text beside the record rather than the record.
func callRaw(t *testing.T, cs *mcp.ClientSession, name string, args any) *mcp.CallToolResult {
	t.Helper()
	res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: name, Arguments: args})
	if err != nil {
		t.Fatal(err)
	}
	return res
}

// TestMCPRendersTheVerdict checks the five ways a speaker is written,
// and the rule underneath them: a bare nick is a nick somebody pinned,
// and nothing else ever renders bare.
//
// The verdict is answered against the pin store as it is when the read
// happens, not as it was when the line was written, so pinning a key
// settles every line it already said. The test pins between two reads
// to say so.
func TestMCPRendersTheVerdict(t *testing.T) {
	id := func(t *testing.T) key.EndpointID {
		t.Helper()
		k, err := key.GenerateSecretKey()
		if err != nil {
			t.Fatal(err)
		}
		return key.EndpointID(k.Public())
	}
	alice, mallory := id(t), id(t)
	root := chatDir(t,
		"@k="+alice.String()+" 2026-01-01T00:00:00Z <alice> it is me",
		"@k="+alice.String()+" 2026-01-01T00:00:01Z <bob> and this is me too",
		"@k="+mallory.String()+" 2026-01-01T00:00:02Z <alice> no, it is me",
		"@k="+mallory.String()+" 2026-01-01T00:00:03Z <dave> nobody knows me",
		"2026-01-01T00:00:04Z <carol> nobody signed this",
	)

	// Before anything is pinned there is nobody to impersonate, so the
	// two claims to alice are both merely unknown - and neither is
	// bare, because unknown is not a reason to trust a name.
	said := text2(callRaw(t, session(t, root), "irc_read", readIn{Target: "#go"}))
	for _, want := range []string{
		"<alice[" + shortKey(alice.String()) + "]> it is me",
		"<alice[" + shortKey(mallory.String()) + "]> no, it is me",
		"<carol ?> nobody signed this",
	} {
		if !strings.Contains(said, want) {
			t.Errorf("before pinning, the answer does not hold %q:\n%s", want, said)
		}
	}
	if strings.Contains(said, "<alice> ") {
		t.Errorf("an unpinned key rendered bare:\n%s", said)
	}

	writePeers(t, root, map[key.EndpointID]string{alice: "alice"})

	cs := session(t, root)
	got := call[linesOut](t, cs, "irc_read", readIn{Target: "#go"})
	for i, w := range []struct{ verdict, as string }{
		{"pinned", "alice"},
		{"renamed", "alice"},
		{"claimed", ""},
		{"unknown", ""},
		{"unattributed", ""},
	} {
		if got.Lines[i].Verdict != w.verdict || got.Lines[i].As != w.as {
			t.Errorf("line %d verdict = %q, %q; want %q, %q",
				i, got.Lines[i].Verdict, got.Lines[i].As, w.verdict, w.as)
		}
	}

	said = text2(callRaw(t, cs, "irc_read", readIn{Target: "#go"}))
	for _, want := range []string{
		"<alice> it is me",
		"<bob[" + shortKey(alice.String()) + "] is alice> and this is me too",
		"<alice[" + shortKey(mallory.String()) + "] not alice> no, it is me",
		"<dave[" + shortKey(mallory.String()) + "]> nobody knows me",
		"<carol ?> nobody signed this",
	} {
		if !strings.Contains(said, want) {
			t.Errorf("after pinning, the answer does not hold %q:\n%s", want, said)
		}
	}
	// The line that was already in the log before the pin is the one
	// this is about: a verdict is a fact about the store now.
	if !strings.Contains(said, "<alice> it is me") {
		t.Error("pinning a key did not settle the lines it had already said")
	}
}

// TestMCPSendSaysWhenItSplits checks the two halves of the answer to a
// line too long for one message.
//
// The tool used to answer for what was asked - one line - while the log
// grew by two, and nothing in either said they had been one utterance.
// A reader could not tell that from two deliberate messages, and the
// sender was never told it happened.
func TestMCPSendSaysWhenItSplits(t *testing.T) {
	root := chatDir(t)
	cs := session(t, root)

	short := call[sendOut](t, cs, "irc_send", sendIn{Target: "#go", Text: "the eagle has landed"})
	if short.Sent != 1 || short.Lines != 1 {
		t.Errorf("a short line = sent %d, lines %d; want 1, 1", short.Sent, short.Lines)
	}

	long := strings.Repeat("the eagle has landed ", 60)
	got := call[sendOut](t, cs, "irc_send", sendIn{Target: "#go", Text: long})
	if got.Sent != 1 {
		t.Errorf("sent = %d, want 1: one line is one thing said however it travels", got.Sent)
	}
	if got.Lines < 2 {
		t.Fatalf("lines = %d, want more than one: %d bytes does not fit in one message", got.Lines, len(long))
	}
	if want := len(splitText(long)); got.Lines != want {
		t.Errorf("lines = %d, want %d", got.Lines, want)
	}
	// The count is only useful if the answer a model reads says so too.
	said := text2(callRaw(t, cs, "irc_send", sendIn{Target: "#go", Text: long}))
	if !strings.Contains(said, "too long for one message") {
		t.Errorf("the text of the answer does not mention the split:\n%s", said)
	}
}

// TestMCPParseLogWrap checks that a continuation is carried into the
// record, and that a line without the tag is not one.
func TestMCPParseLogWrap(t *testing.T) {
	k := "@k=" + keyBob + " "
	for _, tt := range []struct {
		line string
		want bool
	}{
		{k + "2026-01-01T00:00:00Z <bob> one thing", false},
		{"@k=" + keyBob + ";w=1 2026-01-01T00:00:01Z <bob> and the rest of it", true},
		{"@w=1 2026-01-01T00:00:02Z <bob> unsigned but still a continuation", true},
		{"2026-01-01T00:00:03Z <bob> nothing at all", false},
	} {
		if got := parseLog("#go", tt.line).Wrapped; got != tt.want {
			t.Errorf("parseLog(%q).Wrapped = %v, want %v", tt.line, got, tt.want)
		}
	}
}

// TestTicketLine holds which logged line answers irc_ticket: one the
// server wrote, holding a ticket and nothing else.
func TestTicketLine(t *testing.T) {
	tk := irciroh.TicketKind + "abc"
	for _, tt := range []struct {
		line string
		ok   bool
	}{
		{"2026-01-01T00:00:00Z -irciroh- " + tk, true},
		{"@k=" + keyBob + " 2026-01-01T00:00:00Z -irciroh- " + tk, false},
		{"2026-01-01T00:00:00Z <bob> -irciroh- " + tk, false},
		{"2026-01-01T00:00:00Z -irciroh- " + tk + " and more", false},
		{"2026-01-01T00:00:00Z -irciroh- here is " + tk, false},
	} {
		if got := ticketLine.FindStringSubmatch(tt.line); (got != nil) != tt.ok || tt.ok && got[1] != tk {
			t.Errorf("ticketLine on %q = %q, want ok %v", tt.line, got, tt.ok)
		}
	}
}

// TestKeepTakesOverTheDirectory holds that a view becomes the keeper
// once whatever held the directory lets it go, and says it is a view
// only once while it waits.
func TestKeepTakesOverTheDirectory(t *testing.T) {
	tries := 0
	serve := func() error {
		if tries++; tries < 3 {
			return errLocked
		}
		return nil
	}
	if err := keep(context.Background(), t.TempDir(), serve, time.Millisecond); err != nil {
		t.Fatalf("keep = %v, want nil", err)
	}
	if tries != 3 {
		t.Errorf("served %d times, want 3", tries)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := keep(ctx, t.TempDir(), func() error { return errLocked }, time.Hour); !errors.Is(err, context.Canceled) {
		t.Errorf("keep after cancel = %v, want %v", err, context.Canceled)
	}
}

// TestTheReaderAgreesWithTheWriter runs what the chat writes through
// the parser the mcp server reads it with. Both sides passing their
// own tests proves nothing if they disagree about the format, and this
// is the only place the two meet.
func TestTheReaderAgreesWithTheWriter(t *testing.T) {
	dir := t.TempDir()
	c := &chat{root: dir}
	full := strings.Repeat("ab", 32)
	c.log("#go", full, "<bob> hello")
	c.log("#go", "", "<bob> hello")
	c.log("#go", full, "-bob- notice")
	c.log("#go", "", "-!- bob joined")

	b, err := os.ReadFile(filepath.Join(dir, "#go", "out"))
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimRight(string(b), "\n"), "\n")
	for i, want := range []struct{ kind, from, text, key string }{
		{"message", "bob", "hello", full},
		{"message", "bob", "hello", ""},
		{"notice", "bob", "notice", full},
		{"event", "", "bob joined", ""},
	} {
		got := parseLog("#go", lines[i])
		if got.Kind != want.kind || got.From != want.from || got.Text != want.text || got.Key != want.key {
			t.Errorf("parseLog(%q) = %q, %q, %q, %q; want %q, %q, %q, %q",
				lines[i], got.Kind, got.From, got.Text, got.Key, want.kind, want.from, want.text, want.key)
		}
		if _, err := time.Parse(time.RFC3339, got.Time); err != nil {
			t.Errorf("parseLog(%q) read no time: %v", lines[i], err)
		}
	}
}
