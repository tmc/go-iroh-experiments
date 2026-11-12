package main

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRun(t *testing.T) {
	if testing.Short() {
		t.Skip("local iroh integration")
	}
	if err := runDemo(); err != nil {
		t.Fatal(err)
	}
}

// TestChatProcess also serves as the executable for the subprocess integration.
func TestChatProcess(t *testing.T) {
	if os.Getenv("GROUPCHAT_HELPER") != "1" {
		return
	}
	args := os.Args
	for len(args) > 0 && args[0] != "--" {
		args = args[1:]
	}
	if len(args) == 0 {
		os.Exit(2)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err := command(ctx, args[1:], os.Stdin, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	os.Exit(0)
}

func TestSeparateProcesses(t *testing.T) {
	if testing.Short() {
		t.Skip("local iroh subprocess integration")
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	memberKey := filepath.Join(dir, "member.key")
	ownerKey := filepath.Join(dir, "owner.key")
	invite := filepath.Join(dir, "invite.json")
	child := func(args ...string) *exec.Cmd {
		c := exec.Command(exe, append([]string{"-test.run=^TestChatProcess$", "--"}, args...)...)
		c.Env = append(os.Environ(), "GROUPCHAT_HELPER=1")
		return c
	}
	id, err := child("identity", "-key", memberKey).CombinedOutput()
	if err != nil {
		t.Fatalf("identity: %s: %v", id, err)
	}
	type peer struct {
		cmd    *exec.Cmd
		stdin  io.WriteCloser
		lines  chan string
		stderr bytes.Buffer
	}
	start := func(args ...string) *peer {
		p := &peer{cmd: child(args...), lines: make(chan string, 64)}
		p.cmd.Stderr = &p.stderr
		p.stdin, err = p.cmd.StdinPipe()
		if err != nil {
			t.Fatal(err)
		}
		stdout, e := p.cmd.StdoutPipe()
		if e != nil {
			t.Fatal(e)
		}
		if e := p.cmd.Start(); e != nil {
			t.Fatal(e)
		}
		t.Cleanup(func() { p.cmd.Process.Kill(); p.cmd.Wait() })
		go func() {
			defer close(p.lines)
			s := bufio.NewScanner(stdout)
			for s.Scan() {
				p.lines <- s.Text()
			}
		}()
		return p
	}
	wait := func(p *peer, text string) {
		t.Helper()
		timer := time.NewTimer(10 * time.Second)
		defer timer.Stop()
		for {
			select {
			case line, ok := <-p.lines:
				if !ok {
					t.Fatalf("process ended waiting for %q", text)
				}
				t.Log(line)
				if strings.Contains(line, text) {
					return
				}
			case <-timer.C:
				t.Fatalf("timeout waiting for %q", text)
			}
		}
	}
	send := func(p *peer, text string) {
		t.Helper()
		if _, e := fmt.Fprintln(p.stdin, text); e != nil {
			t.Fatal(e)
		}
	}
	owner := start("owner", "-key", ownerKey, "-allow", strings.TrimSpace(string(id)), "-invite", invite)
	wait(owner, "invitation ready")
	member := start("member", "-key", memberKey, "-invite", invite)
	wait(member, "joined epoch 1")
	wait(owner, "member joined epoch 1")
	send(owner, "hello separate member")
	wait(member, "owner: hello separate member")
	send(member, "hello separate owner")
	wait(owner, "member: hello separate owner")
	send(member, "/rotate")
	wait(member, "rotation accepted")
	send(member, "fresh signer")
	wait(owner, "member: fresh signer")
	send(owner, "fresh epoch reply")
	wait(member, "owner: fresh epoch reply")
	send(member, "/quit")
	if err := member.cmd.Wait(); err != nil {
		t.Fatalf("member: %v: %s", err, member.stderr.String())
	}
	send(owner, "/quit")
	if err := owner.cmd.Wait(); err != nil {
		t.Fatalf("owner: %v: %s", err, owner.stderr.String())
	}
}
