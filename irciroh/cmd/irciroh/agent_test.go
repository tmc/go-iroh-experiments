package main

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestMentions(t *testing.T) {
	for _, tt := range []struct {
		text, nick string
		want       bool
	}{
		{"bot: ping", "bot", true},
		{"hey @bot, look", "bot", true},
		{"ask bot", "bot", true},
		{"BOT!", "bot", true},
		{"robot is not bot spelled short", "robot", true},
		{"robotic", "robot", false},
		{"rebooting", "boot", false},
		{"golang is a language", "go", false},
		{"go: build it", "go", true},
		{"nothing at all", "bot", false},
		{"anything", "", false},
	} {
		if got := mentions(tt.text, tt.nick); got != tt.want {
			t.Errorf("mentions(%q, %q) = %v, want %v", tt.text, tt.nick, got, tt.want)
		}
	}
}

// Keys in these tests are whole ones, because a whole one is what the
// log carries and what anything comparing them must compare.
const (
	bobKey   = "b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0"
	botKey   = "b07b07b07b07b07b07b07b07b07b07b07b07b07b07b07b07b07b07b07b07b07b"
	carolKey = "ca401ca401ca401ca401ca401ca401ca401ca401ca401ca401ca401ca401ca40"
)

func TestSpeech(t *testing.T) {
	for _, tt := range []struct {
		line, nick, key, text string
		ok                    bool
	}{
		{"@k=" + bobKey + " 2026-09-19T00:00:00Z <bob> hello", "bob", bobKey, "hello", true},
		{"@k=" + bobKey + " 2026-09-19T00:00:00Z <bob> <alice> quoted", "bob", bobKey, "<alice> quoted", true},
		// An untagged line is still speech, and it is what every line
		// written before the key was carried through looks like.
		{"2026-09-19T00:00:00Z <bob> hello", "bob", "", "hello", true},
		{"@time=now 2026-09-19T00:00:00Z <bob> hello", "bob", "", "hello", true},
		{"@k=" + bobKey + " 2026-09-19T00:00:00Z -!- bob joined", "", "", "", false},
		{"2026-09-19T00:00:00Z -irciroh- welcome", "", "", "", false},
		{"2026-09-19T00:00:00Z <bob>", "", "", "", false},
		{"@k=" + bobKey, "", "", "", false},
		{"nospace", "", "", "", false},
	} {
		nick, key, text, ok := speech(tt.line)
		if nick != tt.nick || key != tt.key || text != tt.text || ok != tt.ok {
			t.Errorf("speech(%q) = %q, %q, %q, %v; want %q, %q, %q, %v", tt.line, nick, key, text, ok, tt.nick, tt.key, tt.text, tt.ok)
		}
	}
}

// TestSpeechTellsOneNickApart is the reason the key is carried through
// at all: two members may both answer to tmc, and only the endpoint
// after the bang says which of them spoke.
func TestSpeechTellsOneNickApart(t *testing.T) {
	_, first, _, ok := speech("@k=" + bobKey + " 2026-09-19T00:00:00Z <tmc> it is me")
	if !ok {
		t.Fatal("speech did not parse a line with a key")
	}
	nick, second, _, ok := speech("@k=" + carolKey + " 2026-09-19T00:00:01Z <tmc> no, me")
	if !ok {
		t.Fatal("speech did not parse the second line")
	}
	if nick != "tmc" {
		t.Errorf("speech read the nick as %q, want %q", nick, "tmc")
	}
	if first == second {
		t.Errorf("two endpoints claiming one nick both read as %q", first)
	}
}

// TestAgentKnowsItsOwnLines checks the rule that keeps an impostor
// from either silencing the agent or talking it into answering
// itself. The key settles it when both sides have one; the nick is
// what is left when they do not.
func TestAgentKnowsItsOwnLines(t *testing.T) {
	keyed := &agent{nick: "bot", key: botKey}
	for _, tt := range []struct {
		a         *agent
		nick, key string
		want      bool
		why       string
	}{
		{keyed, "bot", botKey, true, "the agent's own line"},
		{keyed, "bot", carolKey, false, "a stranger wearing the agent's nick"},
		{keyed, "carol", botKey, true, "the agent's endpoint under another nick"},
		{keyed, "bot", "", true, "an untagged line falls back to the nick"},
		{&agent{nick: "bot"}, "bot", botKey, true, "an agent with no key has only the nick"},
		{&agent{nick: "bot"}, "carol", carolKey, false, "somebody else"},
	} {
		if got := tt.a.mine(tt.nick, tt.key); got != tt.want {
			t.Errorf("mine(%q, %q) = %v, want %v: %s", tt.nick, tt.key, got, tt.want, tt.why)
		}
	}
}

// TestAgentAnswersOnlyWhenNamed covers the three rules that keep a
// channel with an agent in it habitable: it answers when named, stays
// quiet when it is not, and never answers itself - which is the one
// mistake that fills a channel as fast as the machine allows.
func TestAgentAnswersOnlyWhenNamed(t *testing.T) {
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("no shell to run as the agent")
	}
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "#go"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "nick"), []byte("bot\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "key"), []byte(botKey+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "#go", "out")
	in := filepath.Join(dir, "#go", "in")
	appendLine(t, out, "")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- runAgent(ctx, []string{
			"-dir", dir, "-target", "#go", "-idle", "10ms",
			"--", "sh", "-c", `printf 'pong\n/quit\n'`,
		})
	}()

	// Not named: nothing to answer.
	appendLine(t, out, "@k="+carolKey+" 2026-09-19T00:00:00Z <carol> the bots are restless")
	time.Sleep(500 * time.Millisecond)
	if b, err := os.ReadFile(in); err == nil && len(b) > 0 {
		t.Fatalf("agent answered a line that did not name it: %q", b)
	}

	appendLine(t, out, "@k="+carolKey+" 2026-09-19T00:00:01Z <carol> bot: ping")
	said := waitFor(t, in, "pong")
	if said != "pong" {
		t.Errorf("agent said %q, want %q", said, "pong")
	}
	// A line the command printed is speech, whatever it looks like: a
	// leading slash is escaped rather than run as an IRC command.
	waitFor(t, in, "//quit")

	before, err := os.ReadFile(in)
	if err != nil {
		t.Fatal(err)
	}
	appendLine(t, out, "2026-09-19T00:00:02Z <bot> bot: ping")
	appendLine(t, out, "@k="+botKey+" 2026-09-19T00:00:03Z <bot> bot: ping")
	time.Sleep(500 * time.Millisecond)
	after, err := os.ReadFile(in)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(before) {
		t.Errorf("agent answered itself: %q", strings.TrimPrefix(string(after), string(before)))
	}

	// A stranger who registers the agent's nick is still a stranger,
	// and gets an answer. Reading that as the agent's own line is how
	// a channel is quietly emptied of its agent.
	appendLine(t, out, "@k="+carolKey+" 2026-09-19T00:00:04Z <bot> bot: ping")
	deadline := time.Now().Add(5 * time.Second)
	for {
		now, err := os.ReadFile(in)
		if err != nil {
			t.Fatal(err)
		}
		if len(now) > len(after) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("agent ignored a stranger claiming its nick")
		}
		time.Sleep(chatPoll)
	}

	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("agent did not stop when its context was canceled")
	}
}

// TestAgentNeedsAName checks that an agent with no way to recognize
// its own lines refuses to start rather than talking to itself.
func TestAgentNeedsAName(t *testing.T) {
	dir := t.TempDir()
	err := runAgent(context.Background(), []string{"-dir", dir, "-target", "#go", "--", "true"})
	if err == nil || !strings.Contains(err.Error(), "-name") {
		t.Fatalf("runAgent without a nick = %v, want a complaint naming -name", err)
	}
}

// TestAgentTakesPartOverGossip is the whole arrangement end to end: a
// bridge, a chat keeping its directory, an agent watching that
// directory, and somebody on another node entirely who says the
// agent's name and gets an answer back over the network.
func TestAgentTakesPartOverGossip(t *testing.T) {
	if testing.Short() {
		t.Skip("network test")
	}
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("no shell to run as the agent")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	botAddr, bobAddr := startBridge(t, ctx), startBridge(t, ctx)
	dir := t.TempDir()

	go runChat(ctx, []string{"-server", botAddr, "-dir", dir, "-nick", "bot", "-join", "#go"})
	out := filepath.Join(dir, "#go", "out")
	waitFor(t, out, "bot joined")

	go runAgent(ctx, []string{
		"-dir", dir, "-target", "#go", "-idle", "10ms",
		"--", "sh", "-c", `printf 'pong\n'`,
	})

	// Commands go in the directory's own in file, with no slash: there
	// is nobody there to say anything to.
	appendLine(t, filepath.Join(dir, "in"), "TICKET #go")
	fields := strings.Fields(waitFor(t, filepath.Join(dir, "out"), "-"+serverName+"- "))
	ticket := fields[len(fields)-1]

	bob := dialIRC(t, bobAddr)
	bob.register("bob")
	bob.send("JOIN #go " + ticket)
	bob.expect("bob!", "JOIN #go")
	waitFor(t, out, "joined")

	bob.send("PRIVMSG #go :bot: ping")
	bob.expect("PRIVMSG #go", "pong", "bot!")
}
