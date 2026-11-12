//go:build !unix

package main

import (
	"errors"
	"os"
	"path/filepath"
)

// errLocked is never returned here: without an advisory lock there is
// nothing to find another process holding.
var errLocked = errors.New("another chat is keeping this directory")

// lockChat opens the claim without taking it: there is no portable
// advisory lock here, and refusing to run is worse than running
// unguarded.
func lockChat(root string) (*os.File, error) {
	return os.OpenFile(filepath.Join(root, "lock"), os.O_CREATE|os.O_RDWR, 0o600)
}

// chatting assumes a chat is attached, since without a lock to test
// there is no way to know, and a wrong "nobody is listening" is worse
// than no answer.
func chatting(root string) bool { return true }
