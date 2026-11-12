package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// An agent is a command given a channel to sit in. It follows one
// target's log, and when something is said to it, runs the command
// with the new lines on standard input and says whatever the command
// prints.
//
// That is the whole of the integration, and it is deliberately the
// shape every coding agent already has - read a prompt, write an
// answer:
//
//	irciroh agent -dir ~/irc -target '#go' -- claude -p
//	irciroh agent -dir ~/irc -target '#go' -- codex exec -
//
// The command is started again for each turn rather than kept up, so
// what an agent remembers of the conversation is the log it is handed.
// That is the right way around here: a process that has to stay up to
// hold the thread is a process whose death loses it, and the log
// outlives every reader by design.
type agent struct {
	root    string
	target  string
	nick    string
	key     string
	argv    []string
	mention bool
	idle    time.Duration
	timeout time.Duration
	max     int
}

// runAgent follows a channel and answers it with a command.
func runAgent(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("agent", flag.ExitOnError)
	dir := fs.String("dir", "", "directory a chat is keeping")
	target := fs.String("target", "", "channel or nick to answer in")
	name := fs.String("name", "", "nick to answer to; the chat's own by default")
	mention := fs.Bool("mention", true, "answer only lines that name the nick")
	idle := fs.Duration("idle", 2*time.Second, "quiet to wait for before answering, so that a burst is one turn")
	timeout := fs.Duration("timeout", 5*time.Minute, "how long one turn may run")
	max := fs.Int("max", 20, "most lines to say from one turn")
	history := fs.Bool("history", false, "start at the beginning of the log rather than at its end")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *dir == "" || *target == "" {
		return fmt.Errorf("agent: -dir and -target are required")
	}
	if fs.NArg() == 0 {
		return fmt.Errorf("agent: no command to run; put it after --")
	}
	a := &agent{
		root: *dir, target: *target, nick: *name, argv: fs.Args(),
		mention: *mention, idle: *idle, timeout: *timeout, max: *max,
	}
	if a.nick == "" {
		// Without a name of its own the agent cannot tell its answers
		// from the questions, so it answers itself, and two of those
		// in one channel fill it as fast as the machine allows. It is
		// worth refusing to start over.
		nick, err := chatNick(a.root)
		if err != nil {
			return fmt.Errorf("agent: %w; pass -name", err)
		}
		a.nick = nick
		// The key is the same answer with nobody else able to give
		// it, so the agent takes it when the chat left one. An older
		// directory has none, and the nick still works there.
		a.key, _ = chatKey(a.root)
	}
	if !chatting(a.root) {
		fmt.Fprintf(os.Stderr, "irciroh: warning: no chat is attached to %s; answers will wait for one\n", a.root)
	}
	return a.run(ctx, *history)
}

// run follows the log and takes a turn whenever the channel has asked
// for one and then gone quiet.
func (a *agent) run(ctx context.Context, history bool) error {
	path := filepath.Join(a.root, a.target, "out")
	var at int64
	if !history {
		if fi, err := os.Stat(path); err == nil {
			at = fi.Size()
		}
	}
	var (
		pending []string
		asked   bool
		last    time.Time
	)
	t := time.NewTicker(chatPoll)
	defer t.Stop()
	for {
		lines, next, err := since(path, at)
		if err == nil {
			at = next
		}
		for _, line := range lines {
			nick, key, text, ok := speech(line)
			if !ok || a.mine(nick, key) {
				continue
			}
			pending = append(pending, line)
			last = time.Now()
			if !a.mention || mentions(text, a.nick) {
				asked = true
			}
		}
		// Waiting for quiet is what turns three lines typed in a row
		// into one question. It also costs nothing when there is only
		// ever one line, which is the common case.
		if asked && time.Since(last) >= a.idle {
			a.turn(ctx, pending)
			pending, asked = nil, false
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-t.C:
		}
	}
}

// mine reports whether a logged line is one of the agent's own, which
// is the line it must never answer. The key decides it whenever both
// sides have one: a nick is a claim, and somebody else claiming the
// agent's could otherwise either silence it by wearing its name or,
// worse, hand it its own words to answer and leave the two of them
// filling the channel between them.
func (a *agent) mine(nick, key string) bool {
	if a.key != "" && key != "" {
		return key == a.key
	}
	return nick == a.nick
}

// turn runs the command over what has been said and says the answer.
func (a *agent) turn(ctx context.Context, lines []string) {
	run, cancel := context.WithTimeout(ctx, a.timeout)
	defer cancel()
	cmd := exec.CommandContext(run, a.argv[0], a.argv[1:]...)
	cmd.Stdin = strings.NewReader(strings.Join(lines, "\n") + "\n")
	cmd.Stderr = os.Stderr
	// A command is told where it is standing, so that a wrapper can
	// read further back in the log, or answer somewhere else, without
	// being handed the same three strings a second time.
	cmd.Env = append(os.Environ(),
		"IRC_DIR="+a.root,
		"IRC_TARGET="+a.target,
		"IRC_NICK="+a.nick,
	)
	out, err := cmd.Output()
	if err != nil && len(out) == 0 {
		fmt.Fprintf(os.Stderr, "irciroh: agent %s: %v\n", a.target, err)
		return
	}
	a.reply(out)
}

// reply says what the command printed. Printing nothing says nothing,
// which is how an agent declines: a channel where every line draws an
// answer is a channel nobody can talk in.
func (a *agent) reply(out []byte) {
	var say []string
	for _, line := range strings.Split(string(out), "\n") {
		if line = strings.TrimRight(line, " \t\r"); line == "" {
			continue
		}
		// What the command printed is speech, never IRC. A line
		// beginning with a slash is a command in an in file, and a
		// model that can be talked into printing one could be talked
		// into emptying the channel it was invited to help in.
		if strings.HasPrefix(line, "/") {
			line = "/" + line
		}
		say = append(say, line)
	}
	if len(say) == 0 {
		return
	}
	if len(say) > a.max {
		fmt.Fprintf(os.Stderr, "irciroh: agent %s: %d lines, saying %d\n", a.target, len(say), a.max)
		say = say[:a.max]
	}
	f, err := os.OpenFile(filepath.Join(a.root, a.target, "in"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		fmt.Fprintf(os.Stderr, "irciroh: agent %s: %v\n", a.target, err)
		return
	}
	defer f.Close()
	for _, line := range say {
		fmt.Fprintln(f, line)
	}
}

// mentions reports whether text names nick. It is loose about the
// punctuation around a name - "bot:", "@bot" and "bot," all call one -
// and strict about the letters, so that a bot called go is summoned by
// "go:" and not by "golang".
func mentions(text, nick string) bool {
	if nick == "" {
		return false
	}
	text, nick = strings.ToLower(text), strings.ToLower(nick)
	for i := 0; i+len(nick) <= len(text); {
		j := strings.Index(text[i:], nick)
		if j < 0 {
			return false
		}
		j += i
		if (j == 0 || !isWord(text[j-1])) && (j+len(nick) == len(text) || !isWord(text[j+len(nick)])) {
			return true
		}
		i = j + 1
	}
	return false
}

// isWord reports whether b can appear inside a nick.
func isWord(b byte) bool {
	return b == '_' || b == '-' || b == '[' || b == ']' ||
		'0' <= b && b <= '9' || 'a' <= b && b <= 'z' || 'A' <= b && b <= 'Z'
}
