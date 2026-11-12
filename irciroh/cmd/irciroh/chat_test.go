package main

import (
	"bufio"
	"context"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tmc/go-iroh-experiments/irciroh"
)

// hexKey matches a whole endpoint key, which is what a logged line
// has to carry: the six hex characters a hostmask shows are a label
// for a person to read, not something to compare.
var hexKey = regexp.MustCompile("^[0-9a-f]{64}$")

// TestScan checks the log reader that both wait and the outbox rely on:
// it returns the first matching line and where to resume, and treats a
// file that shrank as one that started over.
func TestScan(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "out")
	write := func(s string) {
		f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		if _, err := f.WriteString(s); err != nil {
			t.Fatal(err)
		}
	}
	any := regexp.MustCompile("")
	eagle := regexp.MustCompile("eagle")

	if _, _, err := scan(path, 0, any); err == nil {
		t.Fatal("scan of a missing log did not report an error")
	}

	write("one\ntwo eagle\nthree\n")
	line, at, err := scan(path, 0, eagle)
	if err != nil {
		t.Fatal(err)
	}
	if line != "two eagle" {
		t.Fatalf("scan = %q, want %q", line, "two eagle")
	}
	if want := int64(len("one\ntwo eagle\n")); at != want {
		t.Fatalf("resume offset = %d, want %d", at, want)
	}
	if line, _, _ := scan(path, at, eagle); line != "" {
		t.Fatalf("scan past the match = %q, want none", line)
	}

	// A partial line is not a line yet, so it is left for the next
	// pass rather than matched half-written.
	write("four eag")
	if line, _, _ := scan(path, at, eagle); line != "" {
		t.Fatalf("scan of a partial line = %q, want none", line)
	}
	write("le\n")
	if line, _, _ := scan(path, at, eagle); line != "four eagle" {
		t.Fatalf("scan after the line finished = %q, want %q", line, "four eagle")
	}

	// Truncation is how a reader says start again.
	if err := os.WriteFile(path, []byte("five\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if line, _, _ := scan(path, at, any); line != "five" {
		t.Fatalf("scan after truncation = %q, want %q", line, "five")
	}
}

// TestChatKeepsTheConversationInFiles drives the whole arrangement: a
// chat attached to one bridge and an ordinary IRC client attached to
// another, talking to each other over gossip, with the chat side
// reading and writing nothing but files.
func TestChatKeepsTheConversationInFiles(t *testing.T) {
	if testing.Short() {
		t.Skip("network test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	aliceAddr, bobAddr := startBridge(t, ctx), startBridge(t, ctx)
	dir := t.TempDir()

	chatCtx, stopChat := context.WithCancel(ctx)
	defer stopChat()
	done := make(chan error, 1)
	go func() {
		done <- runChat(chatCtx, []string{"-server", aliceAddr, "-dir", dir, "-nick", "alice", "-join", "#go"})
	}()

	out := filepath.Join(dir, "#go", "out")
	waitFor(t, out, "alice joined")

	// The welcome carries the node's own endpoint, and it is written
	// down beside the nick so that a program here knows itself by
	// something no one else can register.
	self, err := chatKey(dir)
	if err != nil {
		t.Fatalf("chatKey: %v", err)
	}
	if !hexKey.MatchString(self) {
		t.Errorf("chatKey = %q, want a whole endpoint key", self)
	}

	// A line starting with a slash is a raw IRC command, so everything
	// this tool has no syntax for is still reachable - here the
	// bridge's TICKET extension, whose answer arrives in the log the
	// same way everything else does.
	appendLine(t, filepath.Join(dir, "#go", "in"), "/TICKET #go")
	fields := strings.Fields(waitFor(t, filepath.Join(dir, "out"), "-"+serverName+"- "+irciroh.TicketKind))
	ticket := fields[len(fields)-1]
	if _, err := irciroh.ParseTicket(ticket); err != nil {
		t.Fatalf("logged ticket %q does not parse: %v", ticket, err)
	}

	bob := dialIRC(t, bobAddr)
	bob.register("bob")
	bob.send("JOIN #go " + ticket)
	bob.expect("bob!", "JOIN #go")
	waitFor(t, out, "joined")

	// Sending is appending to a file.
	appendLine(t, filepath.Join(dir, "#go", "in"), "the eagle has landed")
	bob.expect("PRIVMSG #go", "the eagle has landed", "alice!")

	// Reading is the file the other way round.
	bob.send("PRIVMSG #go :copy that")
	line := waitFor(t, out, "copy that")
	nick, key, _, ok := speech(line)
	if !ok || nick != "bob" {
		t.Errorf("logged line %q does not name who said it", line)
	}
	// The key is what the nick above it cannot be trusted for, so the
	// log is only worth reading if the whole endpoint arrived with it.
	if !hexKey.MatchString(key) {
		t.Errorf("logged line %q carries no endpoint for bob", line)
	}
	if key == self {
		t.Errorf("bob's line is stamped with this node's own key %q", key)
	}
	// The body of the line is what it always was, the timestamp
	// included: the tag is in front of it and nothing else moved.
	_, body, _ := cutTags(line)
	if _, err := time.Parse(time.RFC3339, strings.Fields(body)[0]); err != nil {
		t.Errorf("logged line %q does not start with a timestamp: %v", line, err)
	}
	if want := "<bob> copy that"; !strings.HasSuffix(body, want) {
		t.Errorf("logged line %q does not end in %q", line, want)
	}

	// An ordinary client on the same bridge negotiated nothing and
	// must be sent the line it would have been sent before there were
	// any tags. There are irssi sessions attached to these bridges,
	// and a tag one of them did not ask for is a line it cannot read.
	eve := dialIRC(t, aliceAddr)
	eve.register("alice")
	bob.send("PRIVMSG #go :say again")
	plain := eve.expect("PRIVMSG #go", "say again")
	// Byte for byte, not merely untagged: the hostmask still shows the
	// short key, which is what it was always for.
	if want := ":bob!" + key[:6] + "@" + serverName + " PRIVMSG #go :say again"; plain != want {
		t.Errorf("a client that negotiated nothing was sent\n %q\nwant\n %q", plain, want)
	}
	if tagged := waitFor(t, out, "say again"); !strings.HasPrefix(tagged, "@") {
		t.Errorf("the chat, which did negotiate, was sent no tag: %q", tagged)
	}

	// A line too long for one envelope becomes several messages, and
	// the log has to say which of them were one thing said. Without the
	// mark a reader cannot tell this from two deliberate messages, and
	// the sender is not told it happened at all.
	// Distinct words at the two ends: waitFor takes the first line that
	// matches, and every piece of a repeated string matches every other.
	long := "opening " + strings.Repeat("the eagle has landed ", 60) + "closing"
	appendLine(t, filepath.Join(dir, "#go", "in"), long)
	if parts := splitText(long); len(parts) < 2 {
		t.Fatalf("splitText kept %d bytes in one message; the test says nothing", len(long))
	}
	if tail := waitFor(t, out, "closing"); tagValueIn(t, tail, wrapTag) != "1" {
		t.Errorf("the continuation of a split line is not marked: %q", tail)
	}
	// The first piece is not a continuation of anything.
	if head := waitFor(t, out, "opening"); tagValueIn(t, head, wrapTag) != "" {
		t.Errorf("the first piece of a split line is marked as a continuation: %q", head)
	}

	appendLine(t, filepath.Join(dir, "#go", "in"), "/TOPIC #go :flight plan")
	bob.expect("TOPIC #go", "flight plan")

	stopChat()
	select {
	case <-done:
	case <-ctx.Done():
		t.Fatal("chat did not stop when its context was canceled")
	}
}

// appendLine writes one line to an in file the way a caller would.
func appendLine(t *testing.T, path, line string) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := f.WriteString(line + "\n"); err != nil {
		t.Fatal(err)
	}
}

// waitFor blocks until a log holds a line containing want, and returns
// it. It is the test's stand-in for the wait subcommand, which shares
// scan with it.
func waitFor(t *testing.T, path, want string) string {
	t.Helper()
	re := regexp.MustCompile(regexp.QuoteMeta(want))
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		if line, _, err := scan(path, 0, re); err == nil && line != "" {
			return line
		}
		time.Sleep(chatPoll)
	}
	t.Fatalf("waiting for %q in %s", want, path)
	return ""
}

// TestChatDirectoryHasOneOwner checks the claim a chat takes on its
// directory. Two chats on one directory would file every line twice
// and race each other for what is written to the in files, and the
// second one is usually a mistake rather than a plan.
func TestChatDirectoryHasOneOwner(t *testing.T) {
	dir := t.TempDir()
	if chatting(dir) {
		t.Error("an empty directory reports a chat attached to it")
	}
	lock, err := lockChat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !chatting(dir) {
		t.Error("a held directory does not report a chat attached to it")
	}
	if _, err := lockChat(dir); err == nil {
		t.Error("a second chat took a directory another was keeping")
	}
	lock.Close()
	if chatting(dir) {
		t.Error("a released directory still reports a chat attached to it")
	}
	// The claim is a lock rather than a written-down process id
	// precisely so that this is true without anyone cleaning up.
	again, err := lockChat(dir)
	if err != nil {
		t.Fatalf("the directory did not come free when its chat let go: %v", err)
	}
	again.Close()
}

// TestChatNick checks the name a program in the directory answers to,
// which is the one thing it cannot work out from the log alone.
func TestChatNick(t *testing.T) {
	dir := t.TempDir()
	if _, err := chatNick(dir); err == nil {
		t.Error("a directory no chat has attached to reported a nick")
	}
	if err := os.WriteFile(filepath.Join(dir, "nick"), []byte("bot\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if nick, err := chatNick(dir); err != nil || nick != "bot" {
		t.Errorf("chatNick = %q, %v; want %q", nick, err, "bot")
	}
}

// TestChatKey checks the other half of that answer, the one nobody
// else in the channel can give. A directory kept by an older chat has
// only the nick, and saying so is what lets a reader fall back to it.
func TestChatKey(t *testing.T) {
	dir := t.TempDir()
	if _, err := chatKey(dir); err == nil {
		t.Error("a directory no chat has attached to reported a key")
	}
	if err := os.WriteFile(filepath.Join(dir, "nick"), []byte("bot\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := chatKey(dir); err == nil {
		t.Error("a directory with only a nick reported a key")
	}
	if err := os.WriteFile(filepath.Join(dir, "key"), []byte("a1b2c3\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if key, err := chatKey(dir); err != nil || key != "a1b2c3" {
		t.Errorf("chatKey = %q, %v; want %q", key, err, "a1b2c3")
	}
}

// TestSplitKeepsTheKey checks that the endpoint the bridge tagged a
// line with survives the parse, and that a line with no tag - which is
// every line any other IRC server sends - parses as it always did.
func TestSplitKeepsTheKey(t *testing.T) {
	full := strings.Repeat("ab", 32)
	for _, tt := range []struct {
		line, from, key, cmd string
	}{
		{"@" + wireKeyTag + "=" + full + " :bob!a1b2c3@irciroh PRIVMSG #go :hi", "bob", full, "PRIVMSG"},
		{":bob!a1b2c3@irciroh PRIVMSG #go :hi", "bob", "", "PRIVMSG"},
		{":irciroh NOTICE bot :no motd", "irciroh", "", "NOTICE"},
		{"PING :irciroh", "", "", "PING"},
		// A tag the bridge does not send is not a key, and one tag
		// among several is still found.
		{"@time=now :bob!a1b2c3@irciroh PRIVMSG #go :hi", "bob", "", "PRIVMSG"},
		{"@time=now;" + wireKeyTag + "=" + full + " :bob!a1b2c3@irciroh PRIVMSG #go :hi", "bob", full, "PRIVMSG"},
	} {
		from, key, cmd, _ := split(tt.line)
		if from != tt.from || key != tt.key || cmd != tt.cmd {
			t.Errorf("split(%q) = %q, %q, %q; want %q, %q, %q", tt.line, from, key, cmd, tt.from, tt.key, tt.cmd)
		}
	}
}

// TestLogWritesTheKeyInFront pins the three things a reader of this
// log is entitled to assume: the tag is one "@k=" and one space ahead
// of the timestamp, a line with no key carries no tag at all, and the
// body is what it would have been either way. An empty tag value is
// the one thing worse than no tag, because it reads as a key that is
// present and empty rather than as a key nobody knows.
func TestLogWritesTheKeyInFront(t *testing.T) {
	dir := t.TempDir()
	c := &chat{root: dir}
	full := strings.Repeat("ab", 32)
	c.log("", full, "<bob> hello")
	c.log("", "", "<bob> hello")
	c.log("", "", "-irciroh- no motd")

	b, err := os.ReadFile(filepath.Join(dir, "out"))
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimRight(string(b), "\n"), "\n")
	if len(lines) != 3 {
		t.Fatalf("log holds %d lines, want 3", len(lines))
	}
	if want := "@k=" + full + " "; !strings.HasPrefix(lines[0], want) {
		t.Errorf("line %q does not begin with %q", lines[0], want)
	}
	for _, line := range lines[1:] {
		if strings.HasPrefix(line, "@") {
			t.Errorf("a line with no key was tagged anyway: %q", line)
		}
	}
	// The same words, logged with a key and without, differ by the tag
	// and by nothing else.
	_, body, ok := cutTags(lines[0])
	if !ok {
		t.Fatalf("the tagged line %q did not come apart", lines[0])
	}
	_, keyed, _ := strings.Cut(body, " ")
	_, plain, _ := strings.Cut(lines[1], " ")
	if keyed != plain {
		t.Errorf("the body differs with the key on: %q against %q", keyed, plain)
	}
}

// TestCapNegotiation checks the promise the tag rests on: a client
// that asked for tags is told it has them, and one that asked for
// something else is refused the lot rather than half of it.
func TestCapNegotiation(t *testing.T) {
	c := &client{}
	if c.request("") || c.tags.Load() {
		t.Error("an empty request was granted")
	}
	if !c.request(capMessageTags) || !c.tags.Load() {
		t.Error("a request for message-tags was not granted")
	}
	if c.request(capMessageTags+" sasl") || !c.tags.Load() {
		t.Error("a request naming a capability the bridge has not was granted, or cost it one it had")
	}
	if !c.request("-"+capMessageTags) || c.tags.Load() {
		t.Error("a client could not give message-tags back")
	}
}

// tagValueIn reads one tag off a logged line, for the tests that care
// what the log wrote rather than what a reader makes of it.
func tagValueIn(t *testing.T, line, name string) string {
	t.Helper()
	tags, _, ok := cutTags(line)
	if !ok {
		return ""
	}
	return tag(tags, name)
}

// TestChatDoesNotReplayItsInFile holds what a restart on a used
// directory must not do. The lines in an in file are commands with
// effects, so a chat that read from the beginning re-ran every JOIN,
// PART and PRIVMSG the directory ever had. What an earlier chat sent is
// recorded beside the file, and a new chat starts there.
//
// PART is the one that hurt: Part calls forget, and a replayed PART
// therefore turns a reconnect into a leave-and-rejoin. Anyone measuring
// what a bare JOIN does on a directory with history was measuring a
// PART they did not send.
func TestChatDoesNotReplayItsInFile(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "#go"), 0o700); err != nil {
		t.Fatal(err)
	}
	write := func(target, line string) {
		t.Helper()
		if err := appendLines(filepath.Join(root, target, "in"), []string{line}); err != nil {
			t.Fatal(err)
		}
	}
	// What an earlier chat on this directory was told, and sent.
	write("", "PART #go")
	write("#go", "and a thing said")
	for _, target := range []string{"", "#go"} {
		path := filepath.Join(root, target, "in")
		fi, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if err := saveSent(path, fi.Size()); err != nil {
			t.Fatal(err)
		}
	}

	var mu sync.Mutex
	var sent strings.Builder
	c := &chat{root: root, w: bufio.NewWriter(writerFunc(func(b []byte) (int, error) {
		mu.Lock()
		defer mu.Unlock()
		return sent.Write(b)
	}))}
	got := func() string {
		mu.Lock()
		defer mu.Unlock()
		return sent.String()
	}

	// Through outbox, not skip directly: the bug was that nothing
	// called skip, and a test that called it itself would pass against
	// the tree that had it.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go c.outbox(ctx)
	time.Sleep(3 * chatPoll)
	if s := got(); s != "" {
		t.Errorf("a new chat re-sent what it found: %q", s)
	}

	// And what is said to the chat that is running now does go.
	write("", "JOIN #go")
	deadline := time.Now().Add(5 * time.Second)
	for !strings.Contains(got(), "JOIN #go") {
		if time.Now().After(deadline) {
			t.Fatalf("sent %q, want the command written after it started", got())
		}
		time.Sleep(10 * time.Millisecond)
	}
	if strings.Contains(got(), "PART") {
		t.Errorf("sent %q, want no sign of the old PART", got())
	}
}

// TestChatSendsWhatWasQueued holds what "queued" promises: a line
// written while no chat is running is sent by the next one, once, and
// not again by the one after.
func TestChatSendsWhatWasQueued(t *testing.T) {
	root := t.TempDir()
	if err := queue(filepath.Join(root, "in"), []string{"JOIN #go"}); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "#go"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := queue(filepath.Join(root, "#go", "in"), []string{"hello"}); err != nil {
		t.Fatal(err)
	}
	run := func() string {
		t.Helper()
		var sent strings.Builder
		c := &chat{root: root, w: bufio.NewWriter(&sent)}
		var said strings.Builder
		at := make(map[string]int64)
		c.skip(at, &said)
		c.drain("", at)
		c.drain("#go", at)
		return sent.String()
	}
	got := run()
	for _, want := range []string{"JOIN #go\r\n", "PRIVMSG #go :hello\r\n"} {
		if !strings.Contains(got, want) {
			t.Errorf("first chat sent %q, want %q", got, want)
		}
	}
	if got := run(); got != "" {
		t.Errorf("second chat sent %q, want nothing", got)
	}
}

// TestChatSkipsOnlyWhatWasThere is the other half: a conversation
// directory that appears after the chat is running has nothing stale in
// it, so it is read from the beginning like anything else.
func TestChatSkipsOnlyWhatWasThere(t *testing.T) {
	root := t.TempDir()
	var mu sync.Mutex
	var sent strings.Builder
	c := &chat{root: root, w: bufio.NewWriter(writerFunc(func(b []byte) (int, error) {
		mu.Lock()
		defer mu.Unlock()
		return sent.Write(b)
	}))}
	at := make(map[string]int64)
	c.skip(at, nil)

	if err := os.MkdirAll(filepath.Join(root, "#new"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := appendLines(filepath.Join(root, "#new", "in"), []string{"hello"}); err != nil {
		t.Fatal(err)
	}
	c.drain("#new", at)
	mu.Lock()
	defer mu.Unlock()
	if !strings.Contains(sent.String(), "PRIVMSG #new :hello") {
		t.Errorf("sent %q, want the line from a directory made after the skip", sent.String())
	}
}

// TestChatSaysWhatItSkipped holds the one thing a person cannot
// otherwise find out. An in file with no record of what was sent from
// it predates the record, and what it holds is skipped rather than
// run, with nothing in the directory afterwards to say so.
func TestChatSaysWhatItSkipped(t *testing.T) {
	root := t.TempDir()
	if err := appendLines(filepath.Join(root, "in"), []string{"JOIN #go"}); err != nil {
		t.Fatal(err)
	}
	c := &chat{root: root}
	var said strings.Builder
	c.skip(make(map[string]int64), &said)
	if !strings.Contains(said.String(), filepath.Join(root, "in")) {
		t.Errorf("said %q, want it to name the file it passed over", said.String())
	}

	// And an empty one is not worth a line: every chat has an in file,
	// and most of them have nothing in it.
	empty := t.TempDir()
	if f, err := os.Create(filepath.Join(empty, "in")); err == nil {
		f.Close()
	}
	said.Reset()
	(&chat{root: empty}).skip(make(map[string]int64), &said)
	if said.String() != "" {
		t.Errorf("said %q about an empty in file", said.String())
	}
}

// TestChatFilesAStrangerByKey holds that a private message is filed
// under its sender's nick only when the nick is a plain name. A path, a
// channel's name or the server's would put the line outside the
// directory, or among somebody else's words.
func TestChatFilesAStrangerByKey(t *testing.T) {
	const k = "abcdef0123456789"
	base := t.TempDir()
	root := filepath.Join(base, "a", "irc")
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}
	c := &chat{root: root}
	for _, nick := range []string{"../../escaped", "..", ".", "#go", "&go", "IRCIROH", `a\b`, "a\x1bb"} {
		c.record("@" + wireKeyTag + "=" + k + " :" + nick + "!abcdef@irciroh PRIVMSG me :from " + nick)
	}
	c.record("@" + wireKeyTag + "=" + k + " :bob!abcdef@irciroh PRIVMSG me :from bob")

	if _, err := os.Stat(filepath.Join(base, "escaped")); err == nil {
		t.Error("a nick wrote outside the directory")
	}
	if _, err := os.Stat(filepath.Join(root, "#go")); err == nil {
		t.Error("a nick wrote into a channel's log")
	}
	b, err := os.ReadFile(filepath.Join(root, "~"+shortKey(k), "out"))
	if err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(string(b), "\n"); n != 8 {
		t.Errorf("filed %d lines under the key, want 8:\n%s", n, b)
	}
	if root, _ := os.ReadFile(filepath.Join(root, "out")); strings.Contains(string(root), "from") {
		t.Errorf("a relayed line reached the directory's own log: %q", root)
	}
	waitFor(t, filepath.Join(root, "bob", "out"), "from bob")
}

// TestDMTarget is the rule behind TestChatFilesAStrangerByKey.
func TestDMTarget(t *testing.T) {
	for _, tt := range []struct{ nick, key, want string }{
		{"bob", "abcdef99", "bob"},
		{"bob", "", "bob"},
		{"../x", "abcdef99", "~abcdef"},
		{"", "abcdef99", "~abcdef"},
		{"#go", "", ""},
		{"irciroh", "abcdef99", "~abcdef"},
		{"a/b", "", ""},
	} {
		if got := dmTarget(tt.nick, tt.key); got != tt.want {
			t.Errorf("dmTarget(%q, %q) = %q, want %q", tt.nick, tt.key, got, tt.want)
		}
	}
}

// TestChatLogHoldsNoControls holds that the log, which is read with
// tail in a terminal, holds nothing a terminal acts on.
func TestChatLogHoldsNoControls(t *testing.T) {
	root := t.TempDir()
	c := &chat{root: root}
	c.record("@" + wireKeyTag + "=abcdef :bob!abcdef@irciroh PRIVMSG #go :red\x1b[31m\rover\x07bell\u009b2J\ttab")
	b, err := os.ReadFile(filepath.Join(root, "#go", "out"))
	if err != nil {
		t.Fatal(err)
	}
	line := strings.TrimSuffix(string(b), "\n")
	if strings.ContainsFunc(line, func(r rune) bool { return r < ' ' && r != '\t' || 0x7f <= r && r <= 0x9f }) {
		t.Errorf("logged %q", line)
	}
	if !strings.HasSuffix(line, "red[31moverbell2J\ttab") {
		t.Errorf("logged %q, want the text with the controls taken out", line)
	}
}

// TestAttachedBridgeRelaysPrivateMessages holds what join and mcp
// promise: a node whose only client is attached in process hears its
// private messages, as one served on a port does.
func TestAttachedBridgeRelaysPrivateMessages(t *testing.T) {
	if testing.Short() {
		t.Skip("network test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	dir := t.TempDir()
	alice := testNode(t, ctx, "alice")
	toChat, toBridge := pipePair()
	newBridge(alice).attach(ctx, toChat)
	go serveChat(ctx, toBridge, dir, "alice", "")

	bob := testNode(t, ctx, "bob")
	if err := bob.SendPrivate(ctx, alice.ID(), alice.Addr(), "hello from bob"); err != nil {
		t.Fatalf("private message to an attached bridge: %v", err)
	}
	waitFor(t, filepath.Join(dir, "bob", "out"), "hello from bob")
}

type writerFunc func([]byte) (int, error)

func (f writerFunc) Write(b []byte) (int, error) { return f(b) }
