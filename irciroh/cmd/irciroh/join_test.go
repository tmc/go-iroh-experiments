package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestChatReadsWhileItWrites holds the property join needs from chat: a
// chat must be reading before it finishes registering, because the
// connection join wires it with has no buffer and whatever answers can
// therefore write its reply while the chat is still writing its
// registration.
//
// This is where a deadlock lived. The chat held one lock across the
// blocked write and the goroutine filing the reply wanted the same lock,
// so neither end moved: the bridge waited to be read and the chat waited
// to be read. Over a socket the kernel's buffer hid it. The test uses a
// pipe on purpose, so that nothing hides it.
func TestChatReadsWhileItWrites(t *testing.T) {
	cli, srv := net.Pipe()
	defer cli.Close()
	// A stand-in bridge, answering each line as it arrives rather than
	// waiting to be asked politely. The real one does the same; this one
	// needs no endpoint to do it.
	go func() {
		defer srv.Close()
		r := bufio.NewReader(srv)
		w := bufio.NewWriter(srv)
		for {
			line, err := r.ReadString('\n')
			if err != nil {
				return
			}
			cmd, params := parseLine(strings.TrimRight(line, "\r\n"))
			t.Logf("bridge read %q -> %s %v", line, cmd, params)
			switch cmd {
			case "CAP":
				if len(params) > 0 && strings.EqualFold(params[0], "REQ") {
					fmt.Fprintf(w, ":%s CAP * ACK :%s\r\n", serverName, capMessageTags)
				}
			case "USER":
				fmt.Fprintf(w, ":%s 001 alpha :welcome to irciroh\r\n", serverName)
				fmt.Fprintf(w, ":%s 002 alpha :your host is %s, running on endpoint %s\r\n", serverName, serverName, strings.Repeat("ab", 32))
			case "JOIN":
				if len(params) > 0 {
					fmt.Fprintf(w, ":alpha!abcdef@%s JOIN %s\r\n", serverName, params[0])
				}
			}
			w.Flush()
		}
	}()

	dir := t.TempDir()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- serveChat(ctx, cli, dir, "alpha", "#go") }()

	t.Cleanup(func() {
		filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
			if err == nil && !d.IsDir() {
				b, _ := os.ReadFile(path)
				t.Logf("%s:\n%s", path, b)
			}
			return nil
		})
	})
	go func() {
		if err := <-done; err != nil {
			t.Logf("serveChat returned: %v", err)
		} else {
			t.Logf("serveChat returned nil")
		}
	}()
	waitFor(t, filepath.Join(dir, "#go", "out"), "alpha joined")

	// Registration got far enough to write down who this node is, which
	// is the part a deadlock would have cost even if the join had landed.
	nick, err := chatNick(dir)
	if err != nil || nick != "alpha" {
		t.Errorf("chatNick = %q, %v; want alpha", nick, err)
	}
	if key, err := chatKey(dir); err != nil || !hexKey.MatchString(key) {
		t.Errorf("chatKey = %q, %v; want the endpoint from the welcome", key, err)
	}

	cancel()
}

// TestJoinWantsADirectory holds join to the one flag it cannot default:
// the directory is the identity, so there is nothing sensible to invent.
func TestJoinWantsADirectory(t *testing.T) {
	if err := runJoin(context.Background(), nil); err == nil {
		t.Fatal("runJoin with no -dir succeeded; want an error")
	}
	// Nothing should have been bound to find that out.
	if _, err := os.Stat(filepath.Join(t.TempDir(), "nick")); err == nil {
		t.Error("runJoin wrote a directory it was not given")
	}
}

// TestServeDirYieldsToAKeeper holds the rule mcp decides by: one
// directory has one keeper, and a second process asking for it is told
// so in a way it can tell apart from a real failure. A view that
// mistook the answer for an error would refuse to read a perfectly good
// log, and one that mistook it for success would file every line twice.
func TestServeDirYieldsToAKeeper(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	dir := filepath.Join(t.TempDir(), "kept")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	lock, err := lockChat(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()

	nf := nodeFlags{bind: "[::1]:0", state: t.TempDir()}
	err = serveDir(ctx, &nf, dir, "")
	if !errors.Is(err, errLocked) {
		t.Fatalf("serveDir on a kept directory = %v, want errLocked", err)
	}
	// The name of the directory is in it, since the caller may be
	// keeping several.
	if !strings.Contains(err.Error(), dir) {
		t.Errorf("error is %q, want it to name %s", err, dir)
	}
	// The claim is asked for before the endpoint, so no node was ever
	// opened - and the key file a node would have minted on its way up
	// is the evidence, since binding one also dials the public relays
	// and publishes an address to a public DNS.
	if _, err := os.Stat(filepath.Join(nf.state, "key")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("a node was opened for a directory another process is keeping (%v)", err)
	}
}

// TestServeDirKeepsAFreeDirectory is the other half of the same rule.
func TestServeDirKeepsAFreeDirectory(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	dir := filepath.Join(t.TempDir(), "free")
	nf := nodeFlags{bind: "[::1]:0", state: t.TempDir()}
	done := make(chan error, 1)
	go func() { done <- serveDir(ctx, &nf, dir, "") }()

	// The nick is the directory's own name, and it only reaches the
	// file through a whole IRC registration across the pipe.
	if got := waitFor(t, filepath.Join(dir, "nick"), "free"); got != "free" {
		t.Errorf("nick file says %q, want the directory's name", got)
	}
	if !chatting(dir) {
		t.Error("chatting says nobody is keeping a directory this is keeping")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(30 * time.Second):
		t.Fatal("serveDir did not stop when its context did")
	}
}

// TestJoinKeepsItsKey checks that the identity survives a restart,
// which is the only thing that makes a pin of it worth making.
func TestJoinKeepsItsKey(t *testing.T) {
	state := t.TempDir()
	run := func() string {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		dir := filepath.Join(t.TempDir(), "scribe")
		nf := nodeFlags{bind: "[::1]:0", state: state}
		done := make(chan error, 1)
		go func() { done <- serveDir(ctx, &nf, dir, "") }()
		key := waitFor(t, filepath.Join(dir, "key"), "")
		cancel()
		<-done
		return strings.TrimSpace(key)
	}
	first, second := run(), run()
	if first != second {
		t.Errorf("the node came back as %s, having been %s", second, first)
	}
	// The secret it came back from is a secret.
	info, err := os.Stat(filepath.Join(state, "key"))
	if err != nil {
		t.Fatal(err)
	}
	if mode := info.Mode().Perm(); mode != 0o600 {
		t.Errorf("key file is mode %#o, want 0600", mode)
	}
}

// TestLoadKeyRefusesAReadableKey checks that a key anyone can read is
// refused rather than quietly repaired.
func TestLoadKeyRefusesAReadableKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "key")
	if _, err := loadKey(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := loadKey(path); err == nil {
		t.Fatal("loaded a world-readable key")
	} else if !strings.Contains(err.Error(), "not a secret") {
		t.Errorf("error is %q, want it to say why", err)
	}
	// Refusing means refusing, not repairing.
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if mode := info.Mode().Perm(); mode != 0o644 {
		t.Errorf("key file is now mode %#o; it was left as it was found", mode)
	}
}

// TestKeyInState checks the rule that a node asked to forget everything
// forgets its name too.
func TestKeyInState(t *testing.T) {
	for _, tt := range []struct {
		name string
		in   nodeFlags
		want string
	}{
		{"state holds the key", nodeFlags{state: "/s"}, filepath.Join("/s", "key")},
		{"an asked-for key wins", nodeFlags{state: "/s", keyPath: "/k"}, "/k"},
		{"no state, no key", nodeFlags{}, ""},
		{"no state but an asked-for key", nodeFlags{keyPath: "/k"}, "/k"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			nf := tt.in
			nf.keyInState()
			if nf.keyPath != tt.want {
				t.Errorf("key path is %q, want %q", nf.keyPath, tt.want)
			}
		})
	}
}

// TestAnnounceSaysWhatLeavesTheMachine holds the line a node prints as
// it comes up. mcp reads a directory and now also dials: that is fine,
// and doing it without saying so is not.
func TestAnnounceSaysWhatLeavesTheMachine(t *testing.T) {
	id := testKey(t, 7)
	for _, tt := range []struct {
		name string
		in   nodeFlags
		want []string
	}{
		{"both", nodeFlags{relay: true, rendezvous: true}, []string{"relay", "publishing"}},
		{"relay only", nodeFlags{relay: true}, []string{"relay"}},
		{"rendezvous only", nodeFlags{rendezvous: true}, []string{"publishing"}},
		{"neither", nodeFlags{}, []string{"this network only"}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var buf strings.Builder
			tt.in.announce(&buf, id)
			got := buf.String()
			if !strings.Contains(got, id.String()) {
				t.Errorf("announced %q without naming the node", got)
			}
			for _, want := range tt.want {
				if !strings.Contains(got, want) {
					t.Errorf("announced %q, want it to mention %q", got, want)
				}
			}
			if tt.in.relay != strings.Contains(got, "relay") {
				t.Errorf("announced %q; relay is %v", got, tt.in.relay)
			}
			if lines := strings.Count(got, "\n"); lines != 1 {
				t.Errorf("announced %d lines, want one: %q", lines, got)
			}
		})
	}
}

// TestWarnOpenListener holds the line serve prints when its bridge can
// be reached from off this machine. The bridge has no authentication of
// its own, so the listen address is the whole of the access rule.
func TestWarnOpenListener(t *testing.T) {
	for _, tt := range []struct {
		addr string
		warn bool
	}{
		{"127.0.0.1:6667", false},
		{"[::1]:6667", false},
		{"0.0.0.0:6667", true},
		{"[::]:6667", true},
		{"192.168.1.10:6667", true},
	} {
		t.Run(tt.addr, func(t *testing.T) {
			ln, err := net.Listen("tcp", tt.addr)
			if err != nil {
				t.Skipf("cannot listen on %s: %v", tt.addr, err)
			}
			defer ln.Close()
			var buf strings.Builder
			warnOpenListener(&buf, ln.Addr())
			if warned := buf.Len() > 0; warned != tt.warn {
				t.Errorf("warned = %v, want %v: %q", warned, tt.warn, buf.String())
			}
			if tt.warn && !strings.Contains(buf.String(), "speaks as this node") {
				t.Errorf("warning is %q, want it to say what the cost is", buf.String())
			}
		})
	}
}

// TestRecallDefaultsOn holds the default to what the documentation and
// the flag's own comment say it is. A default is the one part of a flag
// nothing else exercises: every test that cares about recall sets it,
// so without this the day it flips back is a day nothing goes red.
func TestRecallDefaultsOn(t *testing.T) {
	for _, tt := range []struct {
		args []string
		want bool
	}{
		{nil, true},
		{[]string{"-recall=false"}, false},
		{[]string{"-recall"}, true},
	} {
		var n nodeFlags
		set := flag.NewFlagSet("test", flag.ContinueOnError)
		set.SetOutput(io.Discard)
		n.register(set)
		if err := set.Parse(tt.args); err != nil {
			t.Fatalf("%v: %v", tt.args, err)
		}
		if n.recall != tt.want {
			t.Errorf("irciroh %v: recall = %v, want %v", tt.args, n.recall, tt.want)
		}
	}
}

// TestJoinLogsWhatThisNodeSaid holds the property a join-backed
// directory is read for: what this node said is in it, once, in the
// same form as what everyone else said.
//
// A bridge does not send a line back to the client that spoke it,
// because an ordinary IRC client has already drawn what its user
// typed. Under serve and chat that costs nothing - the log is a second
// client and is sent the line like anybody else - but under join the
// chat is the only client there is, so the log would hold every side
// of the conversation but its own. chat.say writes it locally instead.
// This is the test that says so, and the count is half of it: the day
// that echo arrives from the bridge as well, the line is in the file
// twice and nobody reading one directory would notice.
func TestJoinLogsWhatThisNodeSaid(t *testing.T) {
	if testing.Short() {
		t.Skip("network test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	dir := t.TempDir()
	joinCtx, stop := context.WithCancel(ctx)
	defer stop()
	done := make(chan error, 1)
	// -state is given explicitly because runJoin parses its own flags
	// and the default is the user's own: a test that leaves it out
	// runs as the person's node, with their key and their remembered
	// channels, and joins every one of them. Two of these tests were
	// found sitting in a live channel that way, as a neighbor of
	// somebody's probe.
	go func() { done <- runJoin(joinCtx, []string{"-dir", dir, "-state", t.TempDir(), "-join", "#said"}) }()

	out := filepath.Join(dir, "#said", "out")
	in := filepath.Join(dir, "#said", "in")
	waitFor(t, out, "joined")

	said := "a node should be able to read what it said"
	appendLine(t, in, said)
	line := waitFor(t, out, said)

	// It is logged as speech from this node and not as a server
	// notice, because that is what it was.
	nick, logged, _, ok := speech(line)
	if !ok {
		t.Fatalf("logged %q, which is not a line somebody said", line)
	}
	self, err := chatKey(dir)
	if err != nil {
		t.Fatal(err)
	}
	if logged != self {
		t.Errorf("logged under key %q, want this node's own %q", logged, self)
	}
	if nick == "" {
		t.Errorf("logged %q with no nick", line)
	}

	// Once. A second line, waited for, is what makes the count fair:
	// anything the first one was going to be joined by has had a whole
	// round trip through the same path to arrive.
	appendLine(t, in, "and once is how many times")
	waitFor(t, out, "and once is how many times")
	b, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(string(b), said); n != 1 {
		t.Fatalf("the line was logged %d times, want once", n)
	}
}

// TestJoinLogsWhatItSaidTheLongWay is the same property for the raw
// path. A line written to the root in file, or to a channel's with a
// slash in front of it, is IRC and goes out verbatim; the answer to
// most of those comes back from the server and is logged when it
// arrives. A PRIVMSG has no answer, so a node driven that way - and a
// shell loop appending "PRIVMSG #c :..." to the root in file is the
// ordinary way to drive one - said something the channel heard and its
// own directory does not hold.
//
// The topic is the other half: a command that is not speech must not
// be written down as speech, whatever else is done with it.
func TestJoinLogsWhatItSaidTheLongWay(t *testing.T) {
	if testing.Short() {
		t.Skip("network test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	dir := t.TempDir()
	joinCtx, stop := context.WithCancel(ctx)
	defer stop()
	done := make(chan error, 1)
	go func() { done <- runJoin(joinCtx, []string{"-dir", dir, "-state", t.TempDir(), "-join", "#raw"}) }()

	out := filepath.Join(dir, "#raw", "out")
	waitFor(t, out, "joined")

	// The topic goes first so that the two lines waited for below are
	// the barrier it is read behind.
	topic := "a topic is not something anybody said"
	appendLine(t, filepath.Join(dir, "in"), "TOPIC #raw :"+topic)

	slashed := "spoken through the channel escape hatch"
	appendLine(t, filepath.Join(dir, "#raw", "in"), "/PRIVMSG #raw :"+slashed)
	waitFor(t, out, slashed)

	rooted := "spoken through the root in file"
	appendLine(t, filepath.Join(dir, "in"), "PRIVMSG #raw :"+rooted)
	waitFor(t, out, rooted)

	self, err := chatKey(dir)
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	said := map[string]int{}
	for _, line := range strings.Split(string(b), "\n") {
		if _, key, text, ok := speech(line); ok && key == self {
			said[text]++
		}
	}
	for _, want := range []string{slashed, rooted} {
		if n := said[want]; n != 1 {
			t.Errorf("%q logged as this node's speech %d times, want once", want, n)
		}
	}
	if n := said[topic]; n != 0 {
		t.Errorf("the topic was logged as speech %d times; a command is not something said", n)
	}
}

// TestJoinFilesARefusalWhereTheClaimIs holds the other half of logging
// your own speech. The log says this node said something; it cannot say
// the room heard it, because a PRIVMSG that lands is answered by
// nothing. The one time the network does answer is when it will not
// carry the line - speaking into a channel this node never joined is
// the plain case - and that answer belongs next to the claim rather
// than in the root log, which is not the file anybody reading a channel
// has open.
func TestJoinFilesARefusalWhereTheClaimIs(t *testing.T) {
	if testing.Short() {
		t.Skip("network test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	dir := t.TempDir()
	joinCtx, stop := context.WithCancel(ctx)
	defer stop()
	done := make(chan error, 1)
	go func() { done <- runJoin(joinCtx, []string{"-dir", dir, "-state", t.TempDir(), "-join", "#here"}) }()
	waitFor(t, filepath.Join(dir, "#here", "out"), "joined")

	// A directory for a channel this node is not in. Making one is all
	// it takes to speak into it: the outbox drains every in file under
	// the root, and nothing about a channel directory means membership.
	if err := os.MkdirAll(filepath.Join(dir, "#absent"), 0o700); err != nil {
		t.Fatal(err)
	}
	said := "into a channel this node never joined"
	appendLine(t, filepath.Join(dir, "#absent", "in"), said)

	out := filepath.Join(dir, "#absent", "out")
	waitFor(t, out, said)
	line := waitFor(t, out, "no such channel")
	if _, _, _, ok := speech(line); ok {
		t.Errorf("the refusal is filed as something somebody said: %q", line)
	}

	// And it is not also in the root log, because a line about a
	// channel is filed in that channel like every other one.
	b, err := os.ReadFile(filepath.Join(dir, "out"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "no such channel") {
		t.Errorf("the refusal is in the root log too:\n%s", b)
	}
	// Only a refusal moves. An ordinary reply names a channel too -
	// the roster this node was sent on the way in names #here three
	// times - and those are the protocol talking to this client, which
	// is what the root log is. A rule that swept them into the channel
	// would empty the one file a reader goes to for them.
	if !strings.Contains(string(b), " 353 ") {
		t.Errorf("the names reply left the root log:\n%s", b)
	}
}

// TestOpenRefusesTheUsersOwnStateFromATest holds the guard that makes
// the three -state arguments above unnecessary to remember. The default
// state directory is the person's: their endpoint key, and the channel
// secrets that say what to rejoin. A test that binds on it is not a
// test node, it is theirs.
func TestOpenRefusesTheUsersOwnStateFromATest(t *testing.T) {
	def := defaultStateDir()
	if def == "" {
		t.Skip("no user config directory to refuse")
	}
	nf := nodeFlags{bind: "[::1]:0", state: def}
	_, stop, err := nf.open(context.Background())
	if err == nil {
		stop()
		t.Fatal("a test opened a node on the user's own state directory")
	}
	// The error says what to do about it, because the person reading it
	// is writing a test and has no reason to know this flag exists.
	if !strings.Contains(err.Error(), "-state") {
		t.Errorf("error is %q, want it to name the flag to pass", err)
	}
	// And it is refused before anything is bound: the endpoint dials
	// the public relays and publishes an address as it comes up, so a
	// check that ran after it would be reporting what already happened.
	if !strings.Contains(err.Error(), def) {
		t.Errorf("error is %q, want it to name %s", err, def)
	}
}
