package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestAddressed holds the rule that decides what rings. A mention in
// passing must not: an agent interrupted every time somebody says its
// name is one whose owner turns the doorbell off.
func TestAddressed(t *testing.T) {
	const nick = "scribe~19ada2"
	const self = "aabbcc"
	for _, tt := range []struct {
		name string
		line Line
		want bool
	}{
		{"a private message", Line{Kind: "message", Target: "alice", Text: "anything at all"}, true},
		{"addressed in a channel", Line{Kind: "message", Target: "#go", Text: "scribe: is that right?"}, true},
		{"addressed with a comma", Line{Kind: "message", Target: "#go", Text: "scribe, is that right?"}, true},
		{"addressed by the whole nick", Line{Kind: "message", Target: "#go", Text: "scribe~19ada2: hello"}, true},
		{"addressed after a space", Line{Kind: "message", Target: "#go", Text: "  scribe: hello"}, true},
		{"addressed in another case", Line{Kind: "message", Target: "#go", Text: "SCRIBE: hello"}, true},
		{"mentioned in passing", Line{Kind: "message", Target: "#go", Text: "scribe's fix is right"}, false},
		{"named mid-sentence", Line{Kind: "message", Target: "#go", Text: "ask scribe: they know"}, false},
		{"somebody else addressed", Line{Kind: "message", Target: "#go", Text: "scribbler: hello"}, false},
		{"an event", Line{Kind: "event", Target: "#go", Text: "scribe: joined"}, false},
		{"a notice", Line{Kind: "notice", Target: "#go", Text: "scribe: hello"}, false},
		{"a continuation", Line{Kind: "message", Target: "alice", Text: "and the rest of it", Wrapped: true}, false},
		{"this view's own line", Line{Kind: "message", Target: "alice", Text: "hello", Key: self}, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := addressed(tt.line, nick, self); got != tt.want {
				t.Errorf("addressed(%q in %s) = %v, want %v", tt.line.Text, tt.line.Target, got, tt.want)
			}
		})
	}
}

// TestAddressedTo holds the prefix rule on its own, including text
// shorter in bytes than a nick it folds equal to: the Kelvin sign is
// three bytes and lowercases to the one-byte k.
func TestAddressedTo(t *testing.T) {
	for _, tt := range []struct {
		text, nick string
		want       bool
	}{
		{"k", "\u212a", false},
		{"k: hi", "\u212a", false},
		{"\u212a: hi", "k", false},
		{"K: hi", "k", true},
		{"s", "scribe", false},
		{"", "scribe", false},
	} {
		if got := addressedTo(tt.text, tt.nick); got != tt.want {
			t.Errorf("addressedTo(%q, %q) = %v, want %v", tt.text, tt.nick, got, tt.want)
		}
	}
}

// TestWakeCoalesces holds the other half: one ring per interval,
// carrying a count, rather than one per line. #swarm77 runs several
// lines a minute, and a wake apiece would interrupt every turn in a
// fleet continuously.
func TestWakeCoalesces(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "rang")
	w, _ := testWake(t, "echo $1 >> "+out)
	// An interval nothing in the test can outlast while it rings, so
	// that the four below are held whatever the scheduler does, and a
	// short one once they are, so that run sends them promptly.
	w.interval = time.Hour

	// The first ring is immediate: nobody has been woken yet.
	w.ring(1)
	waitRang(t, out, 1)
	// The next four are inside the interval and are counted, not sent.
	for range 4 {
		w.ring(1)
	}
	if got := rang(t, out); len(got) != 1 || got[0] != "1" {
		t.Fatalf("after five messages the command ran %v, want one wake of 1", got)
	}

	w.mu.Lock()
	w.interval, w.last = 100*time.Millisecond, time.Time{}
	w.mu.Unlock()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go w.run(ctx)
	waitRang(t, out, 2)
	if got := rang(t, out); got[1] != "4" {
		t.Errorf("the second wake said %q, want the 4 it held", got[1])
	}

	// And nothing rings when nothing was said.
	time.Sleep(300 * time.Millisecond)
	if got := rang(t, out); len(got) != 2 {
		t.Errorf("the command ran %v, want nothing on an empty interval", got)
	}
}

// TestWakeSaysAFailureOnce holds that a session which has exited does
// not produce a stream of errors.
func TestWakeSaysAFailureOnce(t *testing.T) {
	var mu sync.Mutex
	var log strings.Builder
	w := newWake("exit 3", writerFunc(func(b []byte) (int, error) {
		mu.Lock()
		defer mu.Unlock()
		return log.Write(b)
	}))
	w.interval = 0
	for range 5 {
		w.ring(1)
	}
	said := func() string {
		mu.Lock()
		defer mu.Unlock()
		return log.String()
	}
	waitFunc(t, func() bool { return strings.Contains(said(), "wake command failed") }, "the failing command was never reported")
	// And no more of them, however many rings were spent on it.
	time.Sleep(200 * time.Millisecond)
	mu.Lock()
	defer mu.Unlock()
	if n := strings.Count(log.String(), "wake command failed"); n != 1 {
		t.Errorf("said a failure %d times, want once:\n%s", n, log.String())
	}
}

// TestNoWakeIsNoCommand holds that the flag's zero value does nothing
// at all, since that is what almost every view runs as.
func TestNoWakeIsNoCommand(t *testing.T) {
	for _, s := range []string{"", "   "} {
		if w := newWake(s, os.Stderr); w != nil {
			t.Errorf("newWake(%q) = %v, want nil", s, w)
		}
	}
	// A nil wake is used, not guarded against, so every method has to
	// survive one.
	var w *wake
	w.ring(3)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	w.run(ctx)
}

func rang(t *testing.T, path string) []string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	return strings.Fields(string(b))
}

// waitRang waits for the wake command to have run n times. The command
// runs on its own goroutine, so a test that looked straight after a
// ring would be reading before it ran.
func waitRang(t *testing.T, path string, n int) {
	t.Helper()
	waitFunc(t, func() bool { return len(rang(t, path)) >= n }, fmt.Sprintf("the command ran %d times, want %d", len(rang(t, path)), n))
}

func waitFunc(t *testing.T, ok func() bool, msg string) {
	t.Helper()
	for deadline := time.Now().Add(10 * time.Second); ; time.Sleep(10 * time.Millisecond) {
		if ok() {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal(msg)
		}
	}
}

// recorder collects what a wake said, so that a test which times out
// waiting for the command can print why the command failed. A wake
// command is a shell, and a shell can fail for reasons that have
// nothing to do with this package - a sandbox that refuses process
// creation makes "did not ring" and "could not run" look identical.
type recorder struct {
	mu  sync.Mutex
	buf strings.Builder
}

func (r *recorder) Write(b []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.buf.Write(b)
}

func (r *recorder) String() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.buf.String()
}

// testWake is newWake with its complaints kept where a failing test can
// print them.
func testWake(t *testing.T, command string) (*wake, *recorder) {
	t.Helper()
	rec := new(recorder)
	w := newWake(command, rec)
	t.Cleanup(func() {
		if t.Failed() && rec.String() != "" {
			t.Logf("the wake command said:\n%s", rec.String())
		}
	})
	return w, rec
}

// TestSweepRingsForWhatIsAddressed is the predicate meeting a real log
// through the loop that watches it. It also holds the part a unit test
// of addressed cannot: the sweep that discovers a conversation does not
// ring for everything ever said in it.
func TestSweepRingsForWhatIsAddressed(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "nick"), []byte("scribe~19ada2\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "key"), []byte(strings.Repeat("ab", 32)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	say := func(target string, lines ...string) {
		t.Helper()
		dir := filepath.Join(root, target)
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := appendLines(filepath.Join(dir, "out"), lines); err != nil {
			t.Fatal(err)
		}
	}
	line := func(from, text string) string {
		return "@k=" + strings.Repeat("cd", 32) + " " + time.Now().UTC().Format(time.RFC3339) + " <" + from + "> " + text
	}

	// A history this view has never seen. Discovering it must not ring.
	say("#go", line("alice", "scribe: are you there?"), line("bob", "probably not"))

	out := filepath.Join(t.TempDir(), "rang")
	m := newMCPServer(root)
	m.wake, _ = testWake(t, "echo $1 >> "+out)
	m.wake.interval = time.Millisecond
	// As mcp runs it: the sweep rings, and the run loop sends whatever
	// a ring found a command already in flight for.
	go m.wake.run(ctx)
	m.sweep(ctx)
	if got := rang(t, out); len(got) != 0 {
		t.Fatalf("discovering a conversation rang %v; it must not", got)
	}

	// Now things said while this view is watching.
	say("#go", line("alice", "scribe's fix is right")) // about, not to
	m.sweep(ctx)
	if got := rang(t, out); len(got) != 0 {
		t.Fatalf("a mention in passing rang %v", got)
	}

	say("#go", line("alice", "scribe: is it?"))
	say("alice", line("alice", "and here is a private one"))
	m.sweep(ctx)
	waitFunc(t, func() bool { return total(rang(t, out)) >= 2 }, "two addressed messages were never rung for")
	if got := total(rang(t, out)); got != 2 {
		t.Errorf("rang for %d messages, want 2", got)
	}

	// A line this view said itself is not somebody talking to it.
	say("alice", "@k="+strings.Repeat("ab", 32)+" "+time.Now().UTC().Format(time.RFC3339)+" <scribe~19ada2> my own answer")
	before := total(rang(t, out))
	m.sweep(ctx)
	time.Sleep(200 * time.Millisecond)
	if got := total(rang(t, out)); got != before {
		t.Errorf("this view's own line rang: %d -> %d", before, got)
	}
}

func total(counts []string) int {
	n := 0
	for _, c := range counts {
		v, err := strconv.Atoi(c)
		if err != nil {
			continue
		}
		n += v
	}
	return n
}

// TestWakeDoesNotWaitForTheCommand holds the property the sweep depends
// on: ring is called from the loop that registers new conversations and
// sends the notifications this doorbell exists to supplement, and the
// command is somebody else's program. it2 session send-text against a
// session that has gone modal is exactly the command that sits there. A
// doorbell that jams must not stop the sweep.
func TestWakeDoesNotWaitForTheCommand(t *testing.T) {
	started := make(chan struct{})
	// The command writes nothing. It used to touch a file under
	// t.TempDir() that no assertion read, and since it outlives the
	// test by design, the write raced the directory's removal: one run
	// in ten failed the cleanup with "directory not empty". A command
	// that is only required to still be running needs only to sleep.
	w := newWake("sleep 30", io.Discard)
	w.limit = 30 * time.Second // the goroutine is what is under test, not the timeout
	go func() {
		w.ring(1)
		close(started)
	}()
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("ring did not return while the wake command was running")
	}
}

// TestWakeGivesUpOnAStuckCommand is the other half. The goroutine keeps
// the sweep moving; without a bound, a session that has gone away
// accumulates one stuck process per tick for the life of the view.
func TestWakeGivesUpOnAStuckCommand(t *testing.T) {
	var mu sync.Mutex
	var said string
	w := newWake("sleep 60", writerFunc(func(p []byte) (int, error) {
		mu.Lock()
		defer mu.Unlock()
		said += string(p)
		return len(p), nil
	}))
	w.limit = 200 * time.Millisecond

	start := time.Now()
	w.ring(1)
	waitFunc(t, func() bool {
		mu.Lock()
		defer mu.Unlock()
		return said != ""
	}, "the wake command was never given up on")
	if took := time.Since(start); took > 5*time.Second {
		t.Errorf("gave up after %v, want about %v", took, w.limit)
	}
	mu.Lock()
	defer mu.Unlock()
	if !strings.Contains(said, "gave up") {
		t.Errorf("said %q, want it to say the command was given up on", said)
	}
}

// TestWakeGivesUpOnAHeldPipe is the other way the same command hangs,
// and the one that survives a timeout: the command exits, something it
// left running holds the output pipes open, and Wait blocks on EOF with
// the process already dead. A fire that never returns is worse than the
// synchronous one it replaced, because it leaves firing set and every
// later ring returns quietly.
func TestWakeGivesUpOnAHeldPipe(t *testing.T) {
	var mu sync.Mutex
	var said string
	w := newWake("sleep 60 &", writerFunc(func(p []byte) (int, error) {
		mu.Lock()
		defer mu.Unlock()
		said += string(p)
		return len(p), nil
	}))
	// Longer than WaitDelay, so that what ends the wait is the held
	// pipe and not the deadline. A deadline short enough to land first
	// can also land before a loaded machine has let the shell exit, and
	// then the command really did fail.
	w.limit = 10 * time.Second

	done := make(chan struct{})
	go func() { w.ring(1); close(done) }()
	<-done
	waitFunc(t, func() bool {
		w.mu.Lock()
		defer w.mu.Unlock()
		return !w.firing && !w.last.IsZero()
	}, "fire never returned from a command whose grandchild held the pipe")
	// And nothing is said about it, because nothing went wrong: the
	// command ran and exited 0. Reporting a failure here would call
	// every backgrounding wake command broken.
	mu.Lock()
	defer mu.Unlock()
	if said != "" {
		t.Errorf("said %q about a command that succeeded", said)
	}
}

// TestNoDMInjectionUnlessAsked holds that a view started inside iTerm
// does not type strangers' private messages into the session it runs in
// just because it can tell which session that is.
func TestNoDMInjectionUnlessAsked(t *testing.T) {
	t.Setenv("ITERM_SESSION_ID", "w0t0p0:5B6D2C0E-0000-0000-0000-000000000000")
	fs := flag.NewFlagSet("mcp", flag.ContinueOnError)
	session := dmFlag(fs)
	if err := fs.Parse(nil); err != nil {
		t.Fatal(err)
	}
	if i := newIt2Injector(*session, io.Discard); i != nil {
		t.Fatalf("with no -dm-it2-session, private messages go to %q", i.session)
	}
	if err := fs.Parse([]string{"-dm-it2-session", "5B6D2C0E"}); err != nil {
		t.Fatal(err)
	}
	if i := newIt2Injector(*session, io.Discard); i == nil || i.session != "5B6D2C0E" {
		t.Fatalf("-dm-it2-session 5B6D2C0E gave injector %v", i)
	}
}

// TestInjectorSaysWhoAndCannotBeFlooded holds the DM injector's three
// promises: the text names the key and the verdict beside the claimed
// nick, holds no control characters (a tab becomes a space), and runs
// one it2 at a time, with what arrived meanwhile counted rather than
// started.
func TestInjectorSaysWhoAndCannotBeFlooded(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "fake it2")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	log := filepath.Join(dir, "it2.log")
	release := filepath.Join(dir, "release")
	// A fake it2 that records its last argument and then waits to be
	// let go, so that the test decides when it is busy.
	script := "#!/bin/sh\ndir=${0%/*}\nfor a; do last=$a; done\nprintf '%s\\n' \"$last\" >> \"$dir/it2.log\"\nwhile [ ! -e \"$dir/release\" ]; do sleep 0.01; done\n"
	if err := os.WriteFile(filepath.Join(dir, "it2"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	lines := func() []string {
		b, _ := os.ReadFile(log)
		return strings.Split(strings.TrimSuffix(string(b), "\n"), "\n")
	}

	rec := new(recorder)
	i := newIt2Injector("5B6D2C0E", rec)
	t.Cleanup(func() {
		// Release and reap the fake command before PATH and its files are
		// restored, including when an assertion fails while it is busy.
		if err := os.WriteFile(release, nil, 0o600); err != nil {
			t.Error(err)
		}
		waitFunc(t, func() bool {
			i.mu.Lock()
			defer i.mu.Unlock()
			return !i.busy
		}, "it2 did not finish during cleanup")
		if t.Failed() && rec.String() != "" {
			t.Logf("the injector said:\n%s", rec.String())
		}
	})
	dm := Line{Kind: "message", Target: "bob", From: "bob", Key: keyBob, Verdict: "claimed", Text: "hi\x1b[2J\rthere\tnow"}
	i.send(dm)
	waitFunc(t, func() bool {
		b, _ := os.ReadFile(log)
		i.mu.Lock()
		defer i.mu.Unlock()
		return len(b) > 0 || !i.busy
	}, "it2 neither recorded its input nor finished")
	if b, _ := os.ReadFile(log); len(b) == 0 {
		t.Fatalf("it2 finished before recording its input: %s", rec.String())
	}
	for range 5 {
		i.send(dm)
	}
	got := lines()
	if len(got) != 1 {
		t.Fatalf("it2 ran %d times while busy, want once: %q", len(got), got)
	}
	if want := "irciroh DM from bob[" + shortKey(keyBob) + "] claimed: hi[2Jthere now"; got[0] != want {
		t.Errorf("injected %q, want %q", got[0], want)
	}

	if err := os.WriteFile(release, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	waitFunc(t, func() bool {
		i.mu.Lock()
		defer i.mu.Unlock()
		return !i.busy
	}, "it2 never finished")
	i.send(dm)
	waitFunc(t, func() bool { return len(lines()) == 2 }, "it2 did not run again once free")
	if got := lines()[1]; !strings.HasSuffix(got, "(and 5 more; call irc_read)") {
		t.Errorf("injected %q, want it to count the 5 it dropped", got)
	}
}

// Cancellation releases the injector whether the command recorded its input
// or stalled before recording. exec leaves no child holding the output pipe.
func TestInjectorCancellation(t *testing.T) {
	for _, ready := range []bool{false, true} {
		t.Run(fmt.Sprintf("ready=%v", ready), func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "fake it2")
			if err := os.Mkdir(dir, 0o700); err != nil {
				t.Fatal(err)
			}
			marker := filepath.Join(dir, "ready")
			script := "#!/bin/sh\ndir=${0%/*}\n"
			if ready {
				script += "printf 'ready\\n' > \"$dir/ready\"\n"
			}
			script += "exec /bin/sleep 60\n"
			command := filepath.Join(dir, "it2")
			if err := os.WriteFile(command, []byte(script), 0o755); err != nil {
				t.Fatal(err)
			}
			t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
			rec := new(recorder)
			i := newIt2Injector("5B6D2C0E", rec)
			dm := Line{Kind: "message", Target: "bob", From: "bob", Text: "hello"}
			i.send(dm)
			idle := func() bool {
				i.mu.Lock()
				defer i.mu.Unlock()
				return !i.busy
			}
			// The generic ten-second helper races the command's ten-second
			// deadline. Allow bounded time for the cancellation to be reaped.
			deadline := time.Now().Add(wakeLimit + 5*time.Second)
			for !idle() && time.Now().Before(deadline) {
				time.Sleep(10 * time.Millisecond)
			}
			if !idle() {
				t.Fatal("cancelled it2 did not release the injector")
			}
			if got := rec.String(); !strings.Contains(got, "it2 DM injection failed: signal: killed") {
				t.Fatalf("cancellation log = %q", got)
			}
			_, err := os.Stat(marker)
			if ready && err != nil || !ready && !os.IsNotExist(err) {
				t.Fatalf("ready marker error = %v, ready = %v", err, ready)
			}
			if err := os.WriteFile(command, []byte("#!/bin/sh\ndir=${0%/*}\nprintf 'recovered\\n' > \"$dir/recovered\"\n"), 0o755); err != nil {
				t.Fatal(err)
			}
			i.send(dm)
			waitFunc(t, idle, "it2 did not finish after cancellation")
			if b, err := os.ReadFile(filepath.Join(dir, "recovered")); err != nil || string(b) != "recovered\n" {
				t.Fatalf("recovered command = %q, %v", b, err)
			}
		})
	}
}
