package main

import (
	"context"
	"flag"
	"fmt"
	"path/filepath"
	"strings"
)

// runJoin owns a node and keeps its conversation in files, with no
// listener and no IRC client.
func runJoin(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("join", flag.ExitOnError)
	dir := fs.String("dir", "", "directory to keep the conversation in")
	join := fs.String("join", "", "comma-separated channels to join on start")
	var nf nodeFlags
	nf.register(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *dir == "" {
		return fmt.Errorf("join: -dir is required")
	}
	return serveDir(ctx, &nf, *dir, *join)
}

// serveDir runs a node, a bridge and a chat in one process, so that a
// directory is served by the program that reads it.
//
// Nothing here is new: it is serve and chat, with the loopback socket
// between them replaced by a pipe. That is deliberate. A second
// implementation of the log writer would be a second set of bugs in the
// format every reader of these directories depends on, and the only
// thing the chat needs from its connection is that a bridge be on the
// other end of it.
func serveDir(ctx context.Context, nf *nodeFlags, dir, join string) error {
	nf.keyInState()
	// A node with no name of its own answers to the directory it
	// keeps. The directory is the identity here - it is what a caller
	// is given, what holds the key, and what the pins are about - so
	// the roster should say the same thing the path does, and a node
	// that came up as some constant would be one more name nobody
	// could tell apart from anybody else's.
	if nf.nick == "" {
		nf.nick = strings.TrimSuffix(filepath.Base(dir), string(filepath.Separator))
	}
	// The claim before the endpoint. Binding one dials the public
	// relays and publishes an address to a public DNS, and a process
	// that did that before asking would have done it for a directory
	// it then found somebody else keeping.
	lock, err := keepDir(dir)
	if err != nil {
		return err
	}
	defer lock.Close()

	node, closeNode, err := nf.open(ctx)
	if err != nil {
		return err
	}
	defer closeNode()

	toChat, toBridge := pipePair()
	newBridge(node).attach(ctx, toChat)
	defer toBridge.Close()
	return serveChatLocked(ctx, toBridge, dir, nf.nick, join)
}
