//go:build unix

package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// errLocked reports that another process is already keeping the
// directory. It is a sentinel because a caller that can serve a
// directory or merely look at one has to tell this apart from a real
// failure: finding somebody already there is an answer, not an error.
var errLocked = errors.New("another chat is keeping this directory")

// lockChat takes the exclusive claim on a chat directory, held for as
// long as the returned file is open. One directory is one connection:
// two chats attached to it would file every line twice and race each
// other for what is written to the in files.
//
// The claim is a lock on a file rather than a recorded process id
// because a process that dies still holds its id long enough for
// another to be given it, and nothing at all is left to clean up.
func lockChat(root string) (*os.File, error) {
	f, err := os.OpenFile(filepath.Join(root, "lock"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		return nil, fmt.Errorf("%s: %w", root, errLocked)
	}
	return f, nil
}

// chatting reports whether a chat is attached to a directory. A line
// written to an in file with none attached is not lost - it is sent
// when one arrives - but nothing has heard it yet, and a caller
// waiting for an answer deserves to be told which of those it is.
func chatting(root string) bool {
	f, err := os.Open(filepath.Join(root, "lock"))
	if err != nil {
		return false
	}
	defer f.Close()
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		return true
	}
	syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
	return false
}
