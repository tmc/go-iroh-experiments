package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"
)

// wakeLimit is how long the command is given. It is well under
// wakeInterval so that a session which has gone away cannot accumulate
// a stuck process per tick, and the command that prompted all this -
// it2 session send-text - is exactly the kind that hangs: against a
// session that is modal or gone it sits rather than failing.
const wakeLimit = 10 * time.Second

// wakeInterval is the shortest time between two wakes. An agent that is
// rung for every line said near it is an agent whose owner turns the
// flag off, so the doorbell is coalesced: what arrives in between is
// counted, not queued, and the count is what the command is told.
const wakeInterval = 30 * time.Second

// A wake rings the session an mcp view is running in, so that a message
// addressed to it does not wait for the next time the agent happens to
// read. It runs a command the person who owns the session chose; this
// process knows nothing about terminals.
//
// The command is told how many messages are new and nothing else. That
// is not tidiness: text arriving from the network into a running
// agent's prompt is an injection path, and a doorbell that carries no
// text is not one. The agent reads what was said through irc_read,
// where every line is already labelled with the key that signed it.
//
// For the same reason the rule that decides what rings is not
// authenticated and does not need to be. Anyone can write "scribe:" and
// spend one wake; that buys an interruption and no trust at all.
type wake struct {
	command  string
	interval time.Duration
	limit    time.Duration
	log      io.Writer

	mu       sync.Mutex
	pending  int
	last     time.Time
	firing   bool // one command at a time, whatever else arrives
	reported bool // a failing command is said once, not once a tick
}

// it2Injector is the explicit, opt-in path from a private message to one
// Claude terminal session. It is separate from wake, whose payload is only
// a count and which asks the client to read authenticated log entries.
//
// One it2 runs at a time. A private message that arrives while one is
// running is not queued - somebody sending many would otherwise start
// a process each - but counted, and the next injection says how many
// were not delivered so that the agent knows to read them.
type it2Injector struct {
	session string
	log     io.Writer

	mu     sync.Mutex
	busy   bool
	missed int
}

func newIt2Injector(session string, log io.Writer) *it2Injector {
	session = it2SessionID(session)
	if session == "" {
		return nil
	}
	return &it2Injector{session: session, log: log}
}

// it2SessionID accepts iTerm's WINDOW:SESSION form as well as a bare
// session id. The it2 CLI takes the latter.
func it2SessionID(session string) string {
	session = strings.TrimSpace(session)
	if i := strings.LastIndexByte(session, ':'); i >= 0 {
		session = session[i+1:]
	}
	return strings.TrimSpace(session)
}

// send injects one private message as a natural-language turn. This is the
// deliberately dumb path: the caller has opted into sending directly to a
// named terminal session, and it2 receives the message as an argv element,
// never as shell input.
//
// The text names the sender's key and the pin store's verdict as well
// as the nick it claims, since the nick alone is anybody's to claim,
// and control characters are removed so that what somebody sent cannot
// act on the terminal it is typed into. A tab becomes a space: typed
// into a prompt it would ask for completion.
func (i *it2Injector) send(line Line) {
	if i == nil || line.Target == "" || strings.HasPrefix(line.Target, "#") {
		return
	}
	i.mu.Lock()
	if i.busy {
		i.missed++
		i.mu.Unlock()
		return
	}
	i.busy = true
	missed := i.missed
	i.missed = 0
	i.mu.Unlock()
	from := line.From
	if line.Key != "" {
		from += "[" + shortKey(line.Key) + "]"
	}
	if line.Verdict != "" {
		from += " " + line.Verdict
	}
	text := fmt.Sprintf("irciroh DM from %s: %s", from, line.Text)
	if missed > 0 {
		text += fmt.Sprintf(" (and %d more; call irc_read)", missed)
	}
	text = strings.Map(func(r rune) rune {
		if r == '\t' {
			return ' '
		}
		if r < ' ' || 0x7f <= r && r <= 0x9f {
			return -1
		}
		return r
	}, text)
	go func() {
		defer func() {
			i.mu.Lock()
			i.busy = false
			i.mu.Unlock()
		}()
		ctx, cancel := context.WithTimeout(context.Background(), wakeLimit)
		defer cancel()
		cmd := exec.CommandContext(ctx, "it2", "session", "send-text", i.session,
			"--skip-confirm",
			text)
		if out, err := cmd.CombinedOutput(); err != nil && i.log != nil {
			fmt.Fprintf(i.log, "irciroh: it2 DM injection failed: %v: %s\n", err, strings.TrimSpace(string(out)))
		}
	}()
}

// newWake returns the wake for command, or nil if there is none. A nil
// wake is the ordinary case and every method below tolerates one.
func newWake(command string, log io.Writer) *wake {
	if strings.TrimSpace(command) == "" {
		return nil
	}
	return &wake{command: command, interval: wakeInterval, limit: wakeLimit, log: log}
}

// ring counts n new messages and rings if enough time has passed since
// the last one. What it does not ring for, [wake.run] sends later.
func (w *wake) ring(n int) {
	if w == nil || n <= 0 {
		return
	}
	w.mu.Lock()
	w.pending += n
	due := time.Since(w.last) >= w.interval
	w.mu.Unlock()
	if due {
		// On its own goroutine, because ring is called from the
		// sweep that watches every conversation and the command is
		// somebody else's program. A doorbell that jams must not
		// stop the loop that sends the notifications it exists to
		// supplement. The count is taken under the lock in fire, so
		// two of these cannot spend it twice.
		go w.fire()
	}
}

// run rings for whatever ring could not, until ctx is done.
func (w *wake) run(ctx context.Context) {
	if w == nil {
		return
	}
	t := time.NewTicker(w.interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			w.fire()
		}
	}
}

// fire runs the command once for everything counted so far.
func (w *wake) fire() {
	w.mu.Lock()
	// One at a time. A command that hangs is given up on below, but
	// until then the ring that arrives meanwhile must not start a
	// second copy of it: the session being rung is one session, and a
	// dead one would otherwise collect a process per tick. What this
	// leaves counted is not lost - the next ring or tick sends it.
	n := w.pending
	if w.firing || n == 0 {
		w.mu.Unlock()
		return
	}
	w.pending, w.last, w.firing = 0, time.Now(), true
	w.mu.Unlock()
	defer func() {
		w.mu.Lock()
		w.firing = false
		w.mu.Unlock()
	}()

	// A shell, because the command is one string a person wrote for
	// their own machine, with their own quoting in it. The count is
	// $1 as well as the environment, so that either way of writing it
	// works.
	count := strconv.Itoa(n)
	ctx, cancel := context.WithTimeout(context.Background(), w.limit)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/bin/sh", "-c", w.command, "irciroh-wake", count)
	cmd.Env = append(os.Environ(), "IRCIROH_WAKE_COUNT="+count)
	// Killing the command is not enough to get out of Wait: the output
	// pipes stay open as long as anything the command left behind holds
	// them, and "it2 ... &" in somebody's command string is enough to
	// do that forever. WaitDelay closes them and returns anyway. Without
	// it the timeout above bounds the process and not this call, and a
	// fire that never returns leaves firing set and the doorbell silent
	// for good - a quieter failure than the one it replaced.
	cmd.WaitDelay = time.Second
	out, err := cmd.CombinedOutput()
	// Whether the command worked is what the command did, not what its
	// children are still holding. A wake written the way a person
	// writes one - "it2 ... &" - exits 0 at once and leaves the output
	// pipes open behind it, and that arrives here as the deadline or
	// as ErrWaitDelay depending on which lands first. Neither is the
	// command failing. What is lost is the tail of whatever it
	// printed, which this process was not going to say anyway.
	switch {
	case cmd.ProcessState != nil && cmd.ProcessState.Success():
		err = nil
	case ctx.Err() != nil:
		err = fmt.Errorf("gave up after %v", w.limit)
	}
	if err == nil {
		w.mu.Lock()
		w.reported = false
		w.mu.Unlock()
		return
	}
	// A session that has exited fails every time, and saying so every
	// time would be a worse plague than the one the coalescing is for.
	w.mu.Lock()
	said := w.reported
	w.reported = true
	w.mu.Unlock()
	if !said && w.log != nil {
		fmt.Fprintf(w.log, "irciroh: wake command failed: %v: %s\n", err, strings.TrimSpace(string(out)))
	}
}

// addressed reports whether l is somebody talking to this view rather
// than near it: a private message, or a channel line that opens with
// this view's nick and a : or a , - the convention the server
// instructions already ask agents to follow.
//
// A mention in passing is deliberately not enough. "scribe's fix is
// right" is people talking about you and has to stay quiet; "scribe:
// is that right?" is people talking to you.
func addressed(l Line, nick, key string) bool {
	if l.Kind != "message" || l.Wrapped {
		// Only the first piece of a split utterance carries the
		// prefix, and a split private message would otherwise ring
		// once per frame. One wake per thing said.
		return false
	}
	if key != "" && l.Key == key {
		return false
	}
	if !strings.HasPrefix(l.Target, "#") {
		return true // said to this node and to nobody else
	}
	return addressedTo(l.Text, nick)
}

// addressedTo reports whether text opens by naming nick.
//
// The bare name before a ~ counts too. Nicks in a fleet are suffixed to
// keep two agents of one role apart - it2-bridger-buddy~19ada2 - and
// nobody types the suffix, so a node that insisted on it would never
// hear its own name.
func addressedTo(text, nick string) bool {
	if nick == "" {
		return false
	}
	text = strings.TrimLeft(text, " \t")
	for _, name := range []string{nick, bareNick(nick)} {
		if name == "" || len(text) < len(name) || !strings.EqualFold(text[:len(name)], name) {
			continue
		}
		if rest := text[len(name):]; strings.HasPrefix(rest, ":") || strings.HasPrefix(rest, ",") {
			return true
		}
	}
	return false
}

// bareNick is a nick without the suffix that tells two of one name
// apart.
func bareNick(nick string) string {
	name, _, _ := strings.Cut(nick, "~")
	return name
}
