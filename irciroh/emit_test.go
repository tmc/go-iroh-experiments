package irciroh

import "testing"

// drain empties c.events and reports the kinds it held, in order.
func drain(c *Channel) []EventKind {
	var got []EventKind
	for {
		select {
		case ev := <-c.events:
			got = append(got, ev.Kind)
		default:
			return got
		}
	}
}

// count reports how many of got are k.
func count(got []EventKind, k EventKind) int {
	n := 0
	for _, g := range got {
		if g == k {
			n++
		}
	}
	return n
}

// TestEmitReportsOverflow covers the promise that a reader which falls behind
// is told so. Announcing a lag needs the room the dropped event could not
// find, so emit holds the last slot back for it; without that reserve the
// report is dropped by the same fullness that caused the loss, and the reader
// is left believing it saw everything.
func TestEmitReportsOverflow(t *testing.T) {
	c := &Channel{events: make(chan Event, 8)}

	// Overrun the buffer well past capacity.
	for range 100 {
		c.emit(Event{Kind: Message, Text: "x"})
	}

	got := drain(c)
	if len(got) != cap(c.events) {
		t.Errorf("drained %d events, want %d (a full buffer)", len(got), cap(c.events))
	}
	if n := count(got, Lagged); n != 1 {
		t.Fatalf("drained %d Lagged events, want exactly 1: %v", n, got)
	}
	if got[len(got)-1] != Lagged {
		t.Errorf("last event is %v, want the lag report last: %v", got[len(got)-1], got)
	}
	// Everything ahead of the report is ordinary traffic, in order.
	for i, k := range got[:len(got)-1] {
		if k != Message {
			t.Errorf("event %d is %v, want message", i, k)
		}
	}
}

// TestEmitLagsAgainAfterDrain covers the second burst: once the reader has
// caught up, a later overflow is a new fact and gets its own report.
func TestEmitLagsAgainAfterDrain(t *testing.T) {
	c := &Channel{events: make(chan Event, 4)}

	for range 20 {
		c.emit(Event{Kind: Message})
	}
	if n := count(drain(c), Lagged); n != 1 {
		t.Fatalf("first burst reported %d lags, want 1", n)
	}

	for range 20 {
		c.emit(Event{Kind: Message})
	}
	if n := count(drain(c), Lagged); n != 1 {
		t.Fatalf("second burst reported %d lags, want 1", n)
	}
}

// TestEmitKeepsUpWithAReader covers the ordinary case: a reader that takes
// each event before the next arrives sees all of them and no lag at all. A
// reserve that cost a slot in the steady state would be a bug.
//
// The exchange is lockstep on purpose. emit never blocks, so a producer run
// flat out will outrun any reader and lag by design; "keeping up" is only
// meaningful against a producer that waits.
func TestEmitKeepsUpWithAReader(t *testing.T) {
	c := &Channel{events: make(chan Event, 8)}

	const n = 200
	for range n {
		c.emit(Event{Kind: Message})
		select {
		case ev := <-c.events:
			if ev.Kind != Message {
				t.Fatalf("reader that kept up saw %v", ev.Kind)
			}
		default:
			t.Fatal("event was not delivered to a reader that was ready for it")
		}
	}
}

// TestEmitFillsToReserve covers the boundary: a burst that stops one short of
// capacity is delivered whole, because only the reserve slot is held back.
func TestEmitFillsToReserve(t *testing.T) {
	c := &Channel{events: make(chan Event, 8)}

	for range cap(c.events) - 1 {
		c.emit(Event{Kind: Message})
	}
	got := drain(c)
	if len(got) != cap(c.events)-1 {
		t.Errorf("drained %d, want %d", len(got), cap(c.events)-1)
	}
	if k := count(got, Lagged); k != 0 {
		t.Errorf("a burst that fit reported %d lags, want 0", k)
	}
}

// TestEmitAfterClose covers emit on a channel that has shut down: it must not
// send on the closed events channel.
func TestEmitAfterClose(t *testing.T) {
	c := &Channel{events: make(chan Event, 4), closed: true}
	c.emit(Event{Kind: Message}) // must not panic
	if got := drain(c); len(got) != 0 {
		t.Errorf("emit after close delivered %v", got)
	}
}
