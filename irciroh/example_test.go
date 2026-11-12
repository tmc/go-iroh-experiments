package irciroh_test

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/netip"

	"github.com/tmc/go-iroh-experiments/irciroh"
	"github.com/tmc/go-iroh/gossip"
	"github.com/tmc/go-iroh/iroh"
	"github.com/tmc/go-iroh/key"
)

// bind returns a node on IPv6 loopback with gossip and every protocol
// this package serves registered, plus a function that shuts it all
// down.
func bind(ctx context.Context, nick string, opts ...irciroh.Option) (*irciroh.Node, func()) {
	ep, err := iroh.Bind(ctx, iroh.WithBindAddr(netip.AddrPortFrom(netip.IPv6Loopback(), 0)))
	if err != nil {
		log.Fatal(err)
	}
	g := gossip.NewGossip(ep)
	n, err := irciroh.NewNode(ep, g, nick, opts...)
	if err != nil {
		log.Fatal(err)
	}
	router, err := iroh.NewRouter(ep, map[string]iroh.ProtocolHandler{
		gossip.ALPN:         g.Handler(),
		irciroh.ALPN:        n.Handler(),
		irciroh.InviteALPN:  n.InviteHandler(),
		irciroh.HistoryALPN: n.HistoryHandler(),
	}, nil)
	if err != nil {
		log.Fatal(err)
	}
	return n, func() {
		n.Close()
		router.Shutdown(ctx)
		g.Shutdown(ctx)
		ep.Shutdown(ctx)
	}
}

// await reads c's events until one of kind k from id, and returns it.
func await(c *irciroh.Channel, k irciroh.EventKind, id key.EndpointID) irciroh.Event {
	for ev, err := range c.Events() {
		if err != nil {
			log.Fatal(err)
		}
		if ev.Kind == k && ev.From.ID == id {
			return ev
		}
	}
	log.Fatalf("%s ended before a %v from %s", c.Name(), k, id.Short())
	return irciroh.Event{}
}

// Example joins two nodes to one channel and sends a message from one to
// the other. The ticket alice prints carries the channel name and her
// address; bob would normally receive it out of band.
func Example() {
	ctx := context.Background()

	alice, stopAlice := bind(ctx, "alice")
	defer stopAlice()
	bob, stopBob := bind(ctx, "bob")
	defer stopBob()

	here, err := alice.Join(ctx, "#go", nil)
	if err != nil {
		log.Fatal(err)
	}
	ticket, err := alice.Ticket("#go")
	if err != nil {
		log.Fatal(err)
	}

	invite, err := irciroh.ParseTicket(ticket.String())
	if err != nil {
		log.Fatal(err)
	}
	there, err := bob.JoinTicket(ctx, invite)
	if err != nil {
		log.Fatal(err)
	}
	if err := there.Say(ctx, "hello, #go"); err != nil {
		log.Fatal(err)
	}

	for ev, err := range here.Events() {
		if err != nil {
			log.Fatal(err)
		}
		if ev.Kind == irciroh.Message {
			fmt.Printf("%s: %s\n", ev.From.Nick, ev.Text)
			break
		}
	}
	// Output:
	// bob: hello, #go
}

// ExampleNode_Found founds a sealed channel, whose messages only the
// members of an MLS group can read. The ticket is what admits another
// node: it asks the founder, who adds it to the group.
func ExampleNode_Found() {
	ctx := context.Background()
	alice, stopAlice := bind(ctx, "alice")
	defer stopAlice()
	bob, stopBob := bind(ctx, "bob")
	defer stopBob()

	room, ticket, err := alice.Found(ctx, "#vault", nil)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("sealed:", ticket.Sealed())
	there, err := bob.JoinTicket(ctx, ticket)
	if err != nil {
		log.Fatal(err)
	}
	if err := there.Say(ctx, "only members read this"); err != nil {
		log.Fatal(err)
	}
	ev := await(room, irciroh.Message, bob.ID())
	fmt.Printf("%s: %s\n", ev.From.Nick, ev.Text)
	// Output:
	// sealed: true
	// bob: only members read this
}

// ExampleChannel_Kick removes a member from a sealed channel and bans
// it. The kicked node's channel ends with its own [irciroh.Parted], and
// its ticket no longer admits it.
func ExampleChannel_Kick() {
	ctx := context.Background()
	alice, stopAlice := bind(ctx, "alice")
	defer stopAlice()
	bob, stopBob := bind(ctx, "bob")
	defer stopBob()

	room, ticket, err := alice.Found(ctx, "#vault", nil)
	if err != nil {
		log.Fatal(err)
	}
	there, err := bob.JoinTicket(ctx, ticket)
	if err != nil {
		log.Fatal(err)
	}
	await(room, irciroh.Joined, bob.ID())
	if err := room.Kick(ctx, bob.ID()); err != nil {
		log.Fatal(err)
	}
	ev := await(there, irciroh.Parted, bob.ID())
	fmt.Println("bob parted:", ev.Text)
	_, err = bob.JoinTicket(ctx, ticket)
	fmt.Println("rejoin:", errors.Is(err, irciroh.ErrNotInvited))
	// Output:
	// bob parted: removed
	// rejoin: true
}

// ExampleChannel_Moderate turns on +m, under which only voiced members
// and operators are heard, and then gives bob a voice.
func ExampleChannel_Moderate() {
	ctx := context.Background()
	alice, stopAlice := bind(ctx, "alice")
	defer stopAlice()
	bob, stopBob := bind(ctx, "bob")
	defer stopBob()

	room, ticket, err := alice.Found(ctx, "#vault", nil)
	if err != nil {
		log.Fatal(err)
	}
	there, err := bob.JoinTicket(ctx, ticket)
	if err != nil {
		log.Fatal(err)
	}
	await(room, irciroh.Joined, bob.ID())

	if err := room.Moderate(ctx, true); err != nil {
		log.Fatal(err)
	}
	await(there, irciroh.ModeChanged, alice.ID())
	err = there.Say(ctx, "may I?")
	fmt.Println("moderated:", errors.Is(err, irciroh.ErrModerated))

	if err := room.Grant(ctx, bob.ID(), irciroh.Voiced); err != nil {
		log.Fatal(err)
	}
	await(there, irciroh.RankChanged, bob.ID())
	fmt.Println("bob is", there.Rank(bob.ID()))
	if err := there.Say(ctx, "thank you"); err != nil {
		log.Fatal(err)
	}
	ev := await(room, irciroh.Message, bob.ID())
	fmt.Printf("%s: %s\n", ev.From.Nick, ev.Text)
	// Output:
	// moderated: true
	// bob is voiced
	// bob: thank you
}

// ExampleNode_SendPrivate sends a private message, which travels on a
// direct connection rather than on any channel.
func ExampleNode_SendPrivate() {
	ctx := context.Background()
	alice, stopAlice := bind(ctx, "alice")
	defer stopAlice()
	bob, stopBob := bind(ctx, "bob")
	defer stopBob()

	if err := alice.SendPrivate(ctx, bob.ID(), bob.Addr(), "psst"); err != nil {
		log.Fatal(err)
	}
	for ev, err := range bob.Private() {
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("%s: %s\n", ev.From.Nick, ev.Text)
		break
	}
	// Output:
	// alice: psst
}

// ExampleChannel_Recall asks a peer what was said before this node
// joined. What it serves arrives as [irciroh.Replayed] events, never as
// messages: it is hearsay, signed by the speaker but chosen by the peer.
func ExampleChannel_Recall() {
	ctx := context.Background()
	alice, stopAlice := bind(ctx, "alice", irciroh.WithHistory())
	defer stopAlice()
	bob, stopBob := bind(ctx, "bob", irciroh.WithHistory())
	defer stopBob()

	here, err := alice.Join(ctx, "#go", nil)
	if err != nil {
		log.Fatal(err)
	}
	if err := here.Say(ctx, "said before bob came"); err != nil {
		log.Fatal(err)
	}
	ticket, err := alice.Ticket("#go")
	if err != nil {
		log.Fatal(err)
	}
	there, err := bob.JoinTicket(ctx, ticket)
	if err != nil {
		log.Fatal(err)
	}
	if _, err := there.Recall(ctx, alice.Addr(), 10); err != nil {
		log.Fatal(err)
	}
	ev := await(there, irciroh.Replayed, alice.ID())
	fmt.Printf("%s said, via %s: %s\n", ev.From.Nick, ev.Via.Nick, ev.Text)
	// Output:
	// alice said, via alice: said before bob came
}

// ExampleChannel_SetTopic sets a topic, which every member sees as a
// [irciroh.TopicChanged] event.
func ExampleChannel_SetTopic() {
	ctx := context.Background()
	alice, stopAlice := bind(ctx, "alice")
	defer stopAlice()
	bob, stopBob := bind(ctx, "bob")
	defer stopBob()

	here, err := alice.Join(ctx, "#go", nil)
	if err != nil {
		log.Fatal(err)
	}
	ticket, err := alice.Ticket("#go")
	if err != nil {
		log.Fatal(err)
	}
	there, err := bob.JoinTicket(ctx, ticket)
	if err != nil {
		log.Fatal(err)
	}
	await(here, irciroh.Joined, bob.ID())
	if err := here.SetTopic(ctx, "Go 1.26 is out"); err != nil {
		log.Fatal(err)
	}
	ev := await(there, irciroh.TopicChanged, alice.ID())
	fmt.Println("topic:", ev.Text)
	// Output:
	// topic: Go 1.26 is out
}

// ExampleParseTicket round-trips a ticket through its text form, which
// is what one person hands another to invite them.
func ExampleParseTicket() {
	t, err := irciroh.ParseTicket(irciroh.Ticket{Channel: "#go"}.String())
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(t.Channel, t.Sealed())

	_, err = irciroh.ParseTicket("irciroh-not-a-ticket")
	fmt.Println(errors.Is(err, irciroh.ErrTicket))
	// Output:
	// #go false
	// true
}

// ExampleFold compares channel names as IRC does, with {}|~ the lower
// case of []\^.
func ExampleFold() {
	fmt.Println(irciroh.Fold("#Go[Nuts]"))
	fmt.Println(irciroh.Fold("#go{nuts}") == irciroh.Fold("#GO[NUTS]"))
	// Output:
	// #go{nuts}
	// true
}

// ExampleTopicID shows that a channel's gossip topic follows from its
// name, and that a secret makes it one only the holders can find.
func ExampleTopicID() {
	open := irciroh.TopicID("#go", nil)
	fmt.Println(open == irciroh.TopicID("#GO", nil))
	fmt.Println(open == irciroh.TopicID("#go", []byte("secret")))
	// Output:
	// true
	// false
}
