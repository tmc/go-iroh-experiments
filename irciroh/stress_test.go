package irciroh

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tmc/go-iroh/key"
	"github.com/tmc/go-iroh/netaddr"
)

// TestStress runs four nodes on a public and a sealed channel with every
// mutating call going at once - Say, SetNick, SetTopic, Grant, Kick, Part
// and Join - for a few seconds, then has them make concurrent last
// statements and checks that every node ends up with the same roster,
// nicks, topic, and ranks. Run it under -race.
func TestStress(t *testing.T) {
	if testing.Short() {
		t.Skip("network test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	alice := newStack(t, ctx, "alice")
	bob := newStack(t, ctx, "bob")
	carol := newStack(t, ctx, "carol")
	dave := newStack(t, ctx, "dave")
	for _, s := range []*stack{alice, bob, carol, dave} {
		defer s.close()
	}
	boot := []netaddr.EndpointAddr{alice.Addr()}

	// Everybody on both channels; bob an operator, so that two
	// endpoints can set the topic and rank carol at once.
	room, ticket, err := alice.Found(ctx, "#sealed", nil)
	if err != nil {
		t.Fatal(err)
	}
	rooms := map[*stack]*Channel{alice: room}
	pubs := make(map[*stack]*Channel)
	for _, s := range []*stack{alice, bob, carol, dave} {
		if s != alice {
			if rooms[s], err = s.JoinTicket(ctx, ticket); err != nil {
				t.Fatal(err)
			}
		}
		if pubs[s], err = s.Join(ctx, "#pub", boot); err != nil {
			t.Fatal(err)
		}
	}
	wantRoster(t, ctx, room, alice.ID(), bob.ID(), carol.ID(), dave.ID())
	waitFor(t, ctx, func() bool { return rooms[bob].Rank(bob.ID()) == Ordinary && len(rooms[bob].Members()) == 4 }, "bob seeing the roster")
	if err := room.Grant(ctx, bob.ID(), Operator); err != nil {
		t.Fatal(err)
	}
	waitFor(t, ctx, func() bool { return rooms[bob].Rank(bob.ID()) == Operator }, "bob hearing he is an operator")

	// The churn. Every error is expected somewhere - a Say on a channel
	// being parted, a Grant that loses a race with a kick - so the
	// calls are made for their effects on the others, and only a
	// panic, a race, or a hang is a failure here.
	churn, stop := context.WithTimeout(ctx, 5*time.Second)
	defer stop()
	var wg sync.WaitGroup
	run := func(f func(i int)) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; churn.Err() == nil; i++ {
				f(i)
			}
		}()
	}
	var pmu sync.Mutex // guards pubs while a node parts and rejoins
	pub := func(s *stack) *Channel {
		pmu.Lock()
		defer pmu.Unlock()
		return pubs[s]
	}
	for _, s := range []*stack{alice, bob, carol, dave} {
		run(func(i int) {
			_ = pub(s).Say(churn, fmt.Sprintf("%s %d", s.Nick(), i))
			_ = rooms[s].Say(churn, fmt.Sprintf("sealed %d", i))
		})
		run(func(i int) {
			_ = s.SetNick(fmt.Sprintf("n%s%d", s.ID().Short()[:4], i%7))
			time.Sleep(10 * time.Millisecond)
		})
	}
	for _, s := range []*stack{alice, bob} {
		run(func(i int) {
			_ = rooms[s].SetTopic(churn, fmt.Sprintf("topic %s %d", s.ID().Short(), i))
			_ = rooms[s].Grant(churn, carol.ID(), Rank(i%2))
			time.Sleep(5 * time.Millisecond)
		})
	}
	for _, s := range []*stack{carol} {
		run(func(i int) {
			_ = pub(s).Part(churn, "brb")
			c, err := s.Join(ctx, "#pub", boot)
			if err != nil {
				t.Errorf("%s rejoining #pub: %v", s.Nick(), err)
				return
			}
			pmu.Lock()
			pubs[s] = c
			pmu.Unlock()
			time.Sleep(50 * time.Millisecond)
		})
	}
	// Dave is kicked from the sealed channel part way through and keeps
	// trying to come back, which must keep failing.
	wg.Add(1)
	go func() {
		defer wg.Done()
		time.Sleep(2 * time.Second)
		if err := room.Kick(ctx, dave.ID()); err != nil {
			t.Errorf("Kick: %v", err)
			return
		}
		// Until the commit reaches dave his node is on the channel
		// as far as it knows, and a join returns it.
		for {
			if _, ok := dave.Channel("#sealed"); !ok {
				break
			}
			select {
			case <-ctx.Done():
				t.Error("the kicked node never left the sealed channel")
				return
			case <-time.After(20 * time.Millisecond):
			}
		}
		for churn.Err() == nil {
			if _, err := dave.JoinTicket(churn, ticket); err == nil {
				t.Error("a kicked endpoint rejoined the sealed channel")
				return
			} else if churn.Err() == nil && !errors.Is(err, ErrNotInvited) {
				t.Logf("kicked rejoin: %v", err)
			}
		}
	}()
	wg.Wait()
	if t.Failed() {
		return
	}

	// A last part and rejoin. Parting and rejoining in a loop is what
	// leaves go-iroh gossip (v0.2.1) owing a neighbor answer it never
	// sends, so that the churning node hears #pub and is not heard on
	// it until a neighbor rejoins it; see [Channel.overdue]. Dave, who
	// is kicked, is not also the one churning #pub: a churning node
	// that then leaves a second channel was once seen to stay unheard
	// too, and that has not been looked into.
	if err := pub(carol).Part(ctx, "last"); err != nil {
		t.Fatal(err)
	}
	if pubs[carol], err = carol.Join(ctx, "#pub", boot); err != nil {
		t.Fatal(err)
	}

	// The churn spent every sender's allowance, and a statement a
	// receiver refuses for the rate is gone: it is not resent, so the
	// receiver keeps what it had. Let the allowances refill for the
	// three statements each node makes below.
	time.Sleep(3*sendInterval + time.Second)

	stacks := []*stack{alice, bob, carol, dave}
	members := []*stack{alice, bob, carol}
	ids := func(ss []*stack) []key.EndpointID {
		var out []key.EndpointID
		for _, s := range ss {
			out = append(out, s.ID())
		}
		return out
	}

	// Last statements, made at once: every node renames itself, both
	// operators set the topic and rank carol differently. Whatever wins,
	// it has to win everywhere.
	var last sync.WaitGroup
	for i, s := range stacks {
		last.Add(1)
		go func() {
			defer last.Done()
			if err := s.SetNick(fmt.Sprintf("final%d", i)); err != nil {
				t.Errorf("SetNick: %v", err)
			}
		}()
	}
	last.Wait()

	// The operators' statements go in rounds. A sealed member the
	// founder has not heard from for presenceTimeout is removed and let
	// back in: a grant naming it while it is out is dropped, not
	// remembered, and an operator removed that way comes back without
	// its rank, so its own grants then fail. The founder regrants when
	// that loses one. Under a loaded -race run with the tests'
	// two-second timeout that happens, so the test regrants too, a few
	// times, and fails only if no round converges.
	agreed := func() bool {
		topic, _, _, ok := room.Topic()
		if !ok {
			return false
		}
		for _, s := range members {
			if got, _, _, _ := rooms[s].Topic(); got != topic {
				return false
			}
			if rooms[s].Rank(carol.ID()) != room.Rank(carol.ID()) {
				return false
			}
		}
		return true
	}
	for round := 1; ; round++ {
		for _, s := range members {
			wantRoster(t, ctx, rooms[s], ids(members)...)
		}
		for i, s := range []*stack{alice, bob} {
			last.Add(1)
			go func() {
				defer last.Done()
				if err := rooms[s].SetTopic(ctx, fmt.Sprintf("final topic %d.%d", round, i)); err != nil {
					t.Logf("round %d: SetTopic: %v", round, err)
				}
				if err := rooms[s].Grant(ctx, carol.ID(), Rank((round+i)%2)); err != nil {
					t.Logf("round %d: Grant: %v", round, err)
				}
			}()
		}
		last.Wait()
		settle, stop := context.WithTimeout(ctx, 10*time.Second)
		for !agreed() && settle.Err() == nil {
			time.Sleep(20 * time.Millisecond)
		}
		stop()
		if agreed() {
			break
		}
		var state []string
		for _, s := range members {
			topic, _, _, _ := rooms[s].Topic()
			state = append(state, fmt.Sprintf("%s: topic %q, carol %v, roster %d", s.ID().Short(), topic, rooms[s].Rank(carol.ID()), len(rooms[s].Members())))
		}
		if round == 3 {
			t.Fatalf("the operators' topic and rank did not converge:\n%s", strings.Join(state, "\n"))
		}
		t.Logf("round %d did not converge:\n%s", round, strings.Join(state, "\n"))
		time.Sleep(3*sendInterval + time.Second)
	}

	for _, s := range members {
		wantRoster(t, ctx, rooms[s], ids(members)...)
	}
	for _, s := range stacks {
		wantRoster(t, ctx, pub(s), ids(stacks)...)
	}
	waitFor(t, ctx, func() bool {
		for _, s := range stacks {
			for _, c := range []*Channel{pub(s), rooms[s]} {
				if s == dave && c == rooms[s] {
					continue
				}
				for _, m := range c.Members() {
					if want := nickOf(stacks, m.ID); m.Nick != want {
						return false
					}
				}
			}
		}
		return true
	}, "every node to see every final nick")
	if slices.ContainsFunc(room.Members(), func(m Member) bool { return m.ID == dave.ID() }) {
		t.Fatal("the kicked endpoint is on the founder's roster")
	}
}

// nickOf returns the nick the stack with the given id has now.
func nickOf(stacks []*stack, id key.EndpointID) string {
	for _, s := range stacks {
		if s.ID() == id {
			return s.Nick()
		}
	}
	return ""
}
