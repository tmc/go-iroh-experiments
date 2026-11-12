package main

import (
	"bufio"
	"io"
	"testing"
	"time"
)

// TestPipeWriteDoesNotWaitForAReader is the property the whole type
// exists for. Both ends of this connection answer each other, so a
// write that waited for a read would let the two halves of one process
// hold each other still.
func TestPipeWriteDoesNotWaitForAReader(t *testing.T) {
	a, b := pipePair()
	done := make(chan error, 1)
	go func() {
		_, err := a.Write([]byte("PING :irciroh\r\n"))
		done <- err
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("write blocked with nobody reading")
	}
	line, err := bufio.NewReader(b).ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	if want := "PING :irciroh\r\n"; line != want {
		t.Errorf("read %q, want %q", line, want)
	}
}

// TestPipeClosePaysWhatItOwes checks that a close does not throw away
// what was already written. The last thing a bridge says is often the
// reason it is closing.
func TestPipeClosePaysWhatItOwes(t *testing.T) {
	a, b := pipePair()
	if _, err := a.Write([]byte("ERROR :closing\r\n")); err != nil {
		t.Fatal(err)
	}
	a.Close()
	got, err := io.ReadAll(b)
	if err != nil {
		t.Fatal(err)
	}
	if want := "ERROR :closing\r\n"; string(got) != want {
		t.Errorf("read %q, want %q", got, want)
	}
}

// TestPipeCloseEndsBothDirections checks that closing one end is the
// end of the conversation and not of half of it.
func TestPipeCloseEndsBothDirections(t *testing.T) {
	a, b := pipePair()
	b.Close()
	if _, err := io.ReadAll(a); err != nil {
		t.Fatalf("read after the far end closed: %v", err)
	}
	if _, err := a.Write([]byte("x")); err == nil {
		t.Error("wrote to a closed pipe without an error")
	}
}
