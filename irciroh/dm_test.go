package irciroh

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/tmc/go-iroh/key"
)

// TestPrivateTellsASenderNobodyIsReading checks what a sender is told
// when the path to a peer works and the peer is not listening. The
// acknowledgement means the message was taken, so a receiver whose
// reader has gone away cannot send one - and before it said so, it held
// the sender until the stream died and left it with a bare EOF.
func TestPrivateTellsASenderNobodyIsReading(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	alice := newTestNode(t, ctx, "alice")
	bob := newTestNode(t, ctx, "bob")

	// Nothing ranges over bob's private messages, so fill the queue
	// behind the door the way an absent reader would.
	for len(bob.private) < cap(bob.private) {
		bob.private <- Event{Kind: Message}
	}

	err := alice.SendPrivate(ctx, bob.ID(), alice.PeerAddr(bob.ID()).WithAddrs(bob.Addr().Addrs()...), "anyone there")
	if !errors.Is(err, ErrNotReading) {
		t.Fatalf("SendPrivate to a peer that is not reading = %v, want %v", err, ErrNotReading)
	}
}

// TestPrivateConcurrent checks that private messages sent at once all
// arrive. Each is its own stream and nothing orders two of them, so the
// receiver sees their sequence numbers out of order - and while it
// demanded they advance, all but a few of forty were dropped and their
// senders told only EOF.
func TestPrivateConcurrent(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	alice := newTestNode(t, ctx, "alice")
	bob := newTestNode(t, ctx, "bob")

	const n = 40
	got := make(chan string, n)
	go func() {
		for ev := range bob.Private() {
			got <- ev.Text
		}
	}()
	addr := alice.PeerAddr(bob.ID()).WithAddrs(bob.Addr().Addrs()...)
	errs := make(chan error, n)
	for i := range n {
		go func() {
			errs <- alice.SendPrivate(ctx, bob.ID(), addr, fmt.Sprint(i))
		}()
	}
	for range n {
		if err := <-errs; err != nil {
			t.Error(err)
		}
	}
	seen := make(map[string]bool)
	for range n {
		select {
		case s := <-got:
			if seen[s] {
				t.Errorf("message %s delivered twice", s)
			}
			seen[s] = true
		case <-ctx.Done():
			t.Fatalf("got %d of %d messages", len(seen), n)
		}
	}
}

func TestDMReplay(t *testing.T) {
	sk, err := key.GenerateSecretKey()
	if err != nil {
		t.Fatal(err)
	}
	from := sk.Public().EndpointID()
	at := func(seq uint64) envelope {
		e, err := sign(sk, dmDomain, kindMessage, seq, "alice", "hi")
		if err != nil {
			t.Fatal(err)
		}
		return e
	}
	now := time.Now()
	r := make(dmReplay)
	for _, tt := range []struct {
		name string
		seq  uint64
		now  time.Time
		want bool
	}{
		{"first", 10, now, true},
		{"earlier, unseen", 8, now, true},
		{"later", 12, now, true},
		{"replay", 10, now, false},
		{"reordered replay", 8, now, false},
		{"after idle, forgotten", 10, now.Add(budgetIdle + time.Minute), true},
	} {
		if got := r.accept(from, at(tt.seq), tt.now); got != tt.want {
			t.Errorf("%s: accept(%d) = %v, want %v", tt.name, tt.seq, got, tt.want)
		}
	}
	if len(r) != 1 || len(r[from].seqs) != 1 {
		t.Errorf("after idle the window is %v, want one entry", r[from].seqs)
	}
}

// TestPrivateDropsASilentSender checks that a stream which starts a frame
// and never finishes it is given up on. The receiver set no deadline, so
// a sender could open streams, write a byte of each and hold a goroutine
// per stream for as long as it kept the connection alive.
func TestPrivateDropsASilentSender(t *testing.T) {
	defer func(d time.Duration) { dmTimeout = d }(dmTimeout)
	dmTimeout = 500 * time.Millisecond

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	alice := newTestNode(t, ctx, "alice")
	bob := newTestNode(t, ctx, "bob")

	conn, err := alice.ep.Connect(ctx, alice.PeerAddr(bob.ID()).WithAddrs(bob.Addr().Addrs()...), ALPN)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()
	if _, err := stream.Write([]byte{0, 0}); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := stream.Read(make([]byte, 1))
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("receiver answered half a frame")
		}
	case <-time.After(10 * dmTimeout):
		t.Fatal("receiver still holding a stream that stopped mid-frame")
	}
}
