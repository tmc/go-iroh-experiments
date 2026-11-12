package main

import (
	"strings"
	"testing"
)

// FuzzParseLine checks that parseLine never panics and that what it
// returns is a command and parameters an IRC line can carry: the command
// is upper case and holds no space, and every parameter but a trailing
// one is a non-empty word.
func FuzzParseLine(f *testing.F) {
	for _, s := range []string{
		"PRIVMSG #go :hello there",
		"@time=2026-01-01T00:00:00Z :nick!u@h PRIVMSG #go :hi",
		"@tags",
		":prefix",
		"NICK alice",
		"JOIN #a,#b key",
		" :",
		"mode #go +m",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, line string) {
		cmd, params := parseLine(line)
		if cmd == "" {
			if params != nil {
				t.Fatalf("parseLine(%q) = no command, params %q", line, params)
			}
			return
		}
		if cmd != strings.ToUpper(cmd) || strings.ContainsAny(cmd, " \t\n") {
			t.Fatalf("parseLine(%q) command = %q", line, cmd)
		}
		trailing := strings.Contains(line, " :")
		for i, p := range params {
			if trailing && i == len(params)-1 {
				break
			}
			if p == "" || len(strings.Fields(p)) != 1 {
				t.Fatalf("parseLine(%q) param %d = %q", line, i, p)
			}
		}
	})
}
