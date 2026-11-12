package irciroh

import (
	"context"
	"errors"
	"testing"
	"time"
)

// TestATicketIsNotAnsweredWithAnotherChannel holds what a name is worth.
// A channel's identity is its topic, made from its name and its secret
// together, so one name can stand for several channels. The node map is
// keyed on the name, and it used to answer any join of a name it knew
// with the channel it had - so a bare join could claim a name and every
// later ticket for that name was discarded without being looked at.
//
// The direction of that failure is the unsafe one: the caller holds a
// secret, believes it joined the channel that secret opens, and is put
// on the public channel of the same name, which is the one anybody who
// guesses the name can read.
func TestATicketIsNotAnsweredWithAnotherChannel(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	n := newTestNode(t, ctx, "alice")

	// A bare join, the way a reconnecting client sends one, claims the
	// name with a public channel.
	pub, err := n.JoinTicket(ctx, Ticket{Channel: "#name"})
	if err != nil {
		t.Fatal(err)
	}
	if pub.seal != nil {
		t.Fatal("a join with no secret made a sealed channel")
	}

	// The same name, a different channel.
	other := Ticket{Channel: "#name", Secret: []byte("a secret somebody was given")}
	got, err := n.JoinTicket(ctx, other)
	if !errors.Is(err, ErrOtherChannel) {
		t.Fatalf("joining with a ticket for another channel = %v, %v; want ErrOtherChannel", got, err)
	}
	if got != nil {
		t.Error("a refused join returned a channel")
	}

	// Parting is the way out, and afterwards the ticket is honoured.
	if err := pub.Part(ctx, ""); err != nil {
		t.Fatal(err)
	}
	sealed, err := n.JoinTicket(ctx, other)
	if err != nil {
		t.Fatalf("joining with the ticket after parting: %v", err)
	}
	if sealed == pub {
		t.Error("the ticket was answered with the channel that was parted")
	}
	if sealed.topic.ID() != other.topic() {
		t.Error("the channel that was joined is not the one the ticket named")
	}

	// A bare join names no channel in particular, so it is answered
	// with the one this node is on rather than refused. This is the
	// reconnecting client, which re-joins every channel it had with a
	// bare JOIN because IRC gives it nowhere to keep a ticket.
	bare, err := n.JoinTicket(ctx, Ticket{Channel: "#name"})
	if err != nil || bare != sealed {
		t.Errorf("a bare join of a channel this node is on = %v, %v; want that channel", bare, err)
	}

	// A join of the channel this node really is on is still the same
	// channel, which is what the map is for.
	again, err := n.JoinTicket(ctx, other)
	if err != nil || again != sealed {
		t.Errorf("rejoining the same channel = %v, %v; want the channel it is on", again, err)
	}
}
