package irciroh

import (
	"bytes"
	"context"
	"errors"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/tmc/go-iroh/gossip"
	"github.com/tmc/go-iroh/iroh"
	"github.com/tmc/go-iroh/key"
	"github.com/tmc/go-iroh/postcard"
)

// newHistoryNode returns a node that keeps and serves history, on IPv6
// loopback, with every handler this package has registered.
func newHistoryNode(t *testing.T, ctx context.Context, nick string, opts ...Option) *Node {
	t.Helper()
	ep, err := iroh.Bind(ctx, iroh.WithBindAddr(netip.AddrPortFrom(netip.IPv6Loopback(), 0)))
	if err != nil {
		t.Fatal(err)
	}
	g := gossip.NewGossip(ep)
	n, err := NewNode(ep, g, nick, append([]Option{WithStateDir(t.TempDir())}, opts...)...)
	if err != nil {
		t.Fatal(err)
	}
	router, err := iroh.NewRouter(ep, map[string]iroh.ProtocolHandler{
		gossip.ALPN: g.Handler(),
		ALPN:        n.Handler(),
		InviteALPN:  n.InviteHandler(),
		HistoryALPN: n.HistoryHandler(),
	}, nil)
	if err != nil {
		_ = ep.Shutdown(ctx)
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = n.Close()
		_ = router.Shutdown(ctx)
		g.Shutdown(ctx)
		_ = ep.Shutdown(ctx)
	})
	return n
}

// mustSign returns one signed envelope of the given kind and text. The
// domain is the channel it is to be said in: an envelope signed for one
// channel does not verify in another, so a test that puts a line into a
// real channel's reel has to sign it for that channel.
func mustSign(t *testing.T, sk key.SecretKey, domain [32]byte, k kind, seq uint64, text string) []byte {
	t.Helper()
	e, err := sign(sk, domain, k, seq, "alice", text)
	if err != nil {
		t.Fatal(err)
	}
	b, err := e.encode()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestReel(t *testing.T) {
	now := time.Now()
	line := func(n int) []byte { return bytes.Repeat([]byte{byte(n)}, 8) }
	big := bytes.Repeat([]byte{'x'}, maxRecallBytes/2+1)

	tests := []struct {
		name  string
		keep  []recalled
		limit int
		want  [][]byte
	}{{
		name:  "empty",
		limit: 10,
		want:  [][]byte{},
	}, {
		name:  "oldest first",
		keep:  []recalled{{line(1), now}, {line(2), now}, {line(3), now}},
		limit: 10,
		want:  [][]byte{line(1), line(2), line(3)},
	}, {
		name:  "limit takes the newest",
		keep:  []recalled{{line(1), now}, {line(2), now}, {line(3), now}},
		limit: 2,
		want:  [][]byte{line(2), line(3)},
	}, {
		name:  "line cap drops the oldest",
		keep:  many(maxRecallLines+2, now),
		limit: maxRecallLines + 2,
		want:  want(2, maxRecallLines+2, now),
	}, {
		name:  "byte cap drops the oldest",
		keep:  []recalled{{big, now}, {big, now}},
		limit: 10,
		want:  [][]byte{big},
	}, {
		name:  "age cap drops the stale",
		keep:  []recalled{{line(1), now.Add(-2 * maxRecallAge)}, {line(2), now}},
		limit: 10,
		want:  [][]byte{line(2)},
	}, {
		name:  "everything stale",
		keep:  []recalled{{line(1), now.Add(-2 * maxRecallAge)}},
		limit: 10,
		want:  [][]byte{},
	}}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var r reel
			for _, k := range tt.keep {
				r.keep(k.b, k.at)
			}
			got := r.recent(tt.limit, now)
			if len(got) != len(tt.want) {
				t.Fatalf("recent(%d) returned %d lines, want %d", tt.limit, len(got), len(tt.want))
			}
			for i := range got {
				if !bytes.Equal(got[i], tt.want[i]) {
					t.Errorf("line %d = %q, want %q", i, got[i], tt.want[i])
				}
			}
		})
	}
}

// many returns n distinct lines kept at one time.
func many(n int, at time.Time) []recalled {
	out := make([]recalled, n)
	for i := range out {
		out[i] = recalled{b: []byte{byte(i), byte(i >> 8)}, at: at}
	}
	return out
}

// want returns the lines many produced, from i to n.
func want(i, n int, at time.Time) [][]byte {
	all := many(n, at)
	out := make([][]byte, 0, n-i)
	for _, r := range all[i:] {
		out = append(out, r.b)
	}
	return out
}

func TestReplayable(t *testing.T) {
	sk := testKey(t, 9)
	now := time.Now()

	tampered := mustSign(t, sk, testDomain, kindMessage, 1, "hello")
	tampered[len(tampered)-1] ^= 1

	// A line whose text was edited after signing. The signature covers
	// it, so this is the case the whole design rests on.
	edited := mustSign(t, sk, testDomain, kindMessage, 1, "hello")
	edited = bytes.ReplaceAll(edited, []byte("hello"), []byte("HELLO"))

	stale, err := sign(sk, testDomain, kindMessage, 1, "alice", "old")
	if err != nil {
		t.Fatal(err)
	}
	stale.Time = now.Add(-2 * maxRecallAge).UnixMilli()
	staleB := resign(t, sk, stale)

	ahead, err := sign(sk, testDomain, kindMessage, 1, "alice", "later")
	if err != nil {
		t.Fatal(err)
	}
	ahead.Time = now.Add(2 * maxClockSkew).UnixMilli()
	aheadB := resign(t, sk, ahead)

	tests := []struct {
		name string
		b    []byte
		want bool
	}{
		{"message", mustSign(t, sk, testDomain, kindMessage, 1, "hello"), true},
		{"notice", mustSign(t, sk, testDomain, kindNotice, 2, "hello"), true},
		{"join is not speech", mustSign(t, sk, testDomain, kindJoin, 3, ""), false},
		{"ping is not speech", mustSign(t, sk, testDomain, kindPing, 4, ""), false},
		{"topic is not speech", mustSign(t, sk, testDomain, kindTopic, 5, "hi"), false},
		{"tampered signature", tampered, false},
		{"edited text", edited, false},
		{"older than the cap", staleB, false},
		{"ahead of the clock", aheadB, false},
		{"not an envelope", []byte("hello"), false},
		{"empty", nil, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, ok := replayable(tt.b, testDomain, now); ok != tt.want {
				t.Errorf("replayable = %v, want %v", ok, tt.want)
			}
		})
	}
}

// resign signs an envelope whose fields a test has changed, so that the
// test exercises the check it means to and not the signature.
func resign(t *testing.T, sk key.SecretKey, e envelope) []byte {
	t.Helper()
	msg, err := e.signed(testDomain)
	if err != nil {
		t.Fatal(err)
	}
	e.Sig = sk.Sign(msg).Bytes()
	b, err := e.encode()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestRecallOnJoin is the whole point: a member that was not there sees
// what was said before it arrived, marked as something a peer told it.
func TestRecallOnJoin(t *testing.T) {
	if testing.Short() {
		t.Skip("network test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	alice := newHistoryNode(t, ctx, "alice", WithHistory())
	ach, err := alice.Join(ctx, "#history", nil)
	if err != nil {
		t.Fatal(err)
	}
	live := events(t, ach)
	said := []string{"one", "two", "three"}
	for _, text := range said {
		if err := ach.Say(ctx, text); err != nil {
			t.Fatal(err)
		}
	}
	ticket, err := alice.Ticket("#history")
	if err != nil {
		t.Fatal(err)
	}

	bob := newHistoryNode(t, ctx, "bob", WithHistory())
	bch, err := bob.JoinTicket(ctx, ticket)
	if err != nil {
		t.Fatal(err)
	}
	in := events(t, bch)

	var got []Event
	for range said {
		got = append(got, await(t, ctx, in, ofKind(Replayed), "replayed line"))
	}
	for i, ev := range got {
		if ev.Text != said[i] {
			t.Errorf("replayed line %d = %q, want %q", i, ev.Text, said[i])
		}
		if ev.From.ID != alice.ID() {
			t.Errorf("replayed line %d was signed by %v, want %v", i, ev.From.ID.Short(), alice.ID().Short())
		}
		if ev.Via.ID != alice.ID() {
			t.Errorf("replayed line %d was served by %v, want %v", i, ev.Via.ID.Short(), alice.ID().Short())
		}
		if ev.Was != Message {
			t.Errorf("replayed line %d was %v, want %v", i, ev.Was, Message)
		}
	}

	// Live speech must not look like history, or the distinction the
	// replay is marked with would be worth nothing.
	if err := bch.Say(ctx, "hello"); err != nil {
		t.Fatal(err)
	}
	ev := await(t, ctx, live, ofKind(Message), "live message")
	if !ev.Via.ID.IsZero() {
		t.Errorf("live message carries Via %v, want none", ev.Via.ID.Short())
	}
}

// TestRecallLimit holds a recall to what the caller asked for.
func TestRecallLimit(t *testing.T) {
	if testing.Short() {
		t.Skip("network test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	alice := newHistoryNode(t, ctx, "alice", WithHistory())
	ach, err := alice.Join(ctx, "#limit", nil)
	if err != nil {
		t.Fatal(err)
	}
	for i := range 4 {
		if err := ach.Say(ctx, strings.Repeat("x", i+1)); err != nil {
			t.Fatal(err)
		}
	}
	ticket, err := alice.Ticket("#limit")
	if err != nil {
		t.Fatal(err)
	}

	// Bob keeps no history of his own, which is a separate decision
	// from whether he asks for anyone else's.
	bob := newHistoryNode(t, ctx, "bob")
	bch, err := bob.JoinTicket(ctx, ticket)
	if err != nil {
		t.Fatal(err)
	}
	n, err := bch.Recall(ctx, ticket.Peers[0], 2)
	if err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Errorf("recalled %d lines, want 2", n)
	}
	// The newest are the ones kept, so the two served are the last two
	// said.
	in := events(t, bch)
	for _, want := range []string{"xxx", "xxxx"} {
		if ev := await(t, ctx, in, ofKind(Replayed), "replayed line"); ev.Text != want {
			t.Errorf("replayed %q, want %q", ev.Text, want)
		}
	}
}

// TestRecallLargeAnswer holds the reader's cap against the largest
// answer a server may send: the lines it is allowed to serve plus the
// framing around them, which the byte cap alone does not account for.
func TestRecallLargeAnswer(t *testing.T) {
	if testing.Short() {
		t.Skip("network test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	alice := newHistoryNode(t, ctx, "alice", WithHistory())
	ach, err := alice.Join(ctx, "#full", nil)
	if err != nil {
		t.Fatal(err)
	}
	// Filled by hand: saying this much over gossip would be testing the
	// rate limiter, which has its own tests.
	sk := testKey(t, 9)
	text := strings.Repeat("x", 500)
	for i := range maxRecallLines {
		ach.recall.keep(mustSign(t, sk, ach.domain(), kindMessage, uint64(i+1), text), time.Now())
	}
	ticket, err := alice.Ticket("#full")
	if err != nil {
		t.Fatal(err)
	}
	bob := newHistoryNode(t, ctx, "bob")
	bch, err := bob.JoinTicket(ctx, ticket)
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for range bch.Events() {
		}
	}()
	n, err := bch.Recall(ctx, ticket.Peers[0], maxRecallLines)
	if err != nil {
		t.Fatal(err)
	}
	if n != maxRecallLines {
		t.Errorf("recalled %d lines, want %d", n, maxRecallLines)
	}
}

// TestRecallKeepsNothingWithoutHistory holds the option to its word: a
// node that was not asked to keep history has none to serve.
func TestRecallKeepsNothingWithoutHistory(t *testing.T) {
	if testing.Short() {
		t.Skip("network test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	alice := newHistoryNode(t, ctx, "alice")
	ach, err := alice.Join(ctx, "#quiet", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := ach.Say(ctx, "said and forgotten"); err != nil {
		t.Fatal(err)
	}
	ticket, err := alice.Ticket("#quiet")
	if err != nil {
		t.Fatal(err)
	}
	bob := newHistoryNode(t, ctx, "bob", WithHistory())
	bch, err := bob.JoinTicket(ctx, ticket)
	if err != nil {
		t.Fatal(err)
	}
	if n, err := bch.Recall(ctx, ticket.Peers[0], 10); !errors.Is(err, ErrNoHistory) {
		t.Fatalf("recall returned (%d, %v), want %v", n, err, ErrNoHistory)
	}
}

// TestRecallSealed holds the rule that a sealed channel's words stay
// inside its key schedule, from both ends.
func TestRecallSealed(t *testing.T) {
	if testing.Short() {
		t.Skip("network test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	alice := newHistoryNode(t, ctx, "alice", WithHistory())
	ach, ticket, err := alice.Found(ctx, "#sealed", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := ach.Say(ctx, "secret"); err != nil {
		t.Fatal(err)
	}
	if _, err := ach.Recall(ctx, ticket.Peers[0], 10); !errors.Is(err, ErrNotSealed) {
		t.Errorf("recall on a sealed channel returned %v, want %v", err, ErrNotSealed)
	}
	// A sealed channel keeps nothing, so the refusal to serve one is
	// held here against a reel filled by hand: without that this would
	// pass on the reel being empty and say nothing about the rule.
	ach.recall.keep(mustSign(t, testKey(t, 9), ach.domain(), kindMessage, 1, "secret"), time.Now())
	h := historyHandler{node: alice, serving: make(chan struct{}, maxRecallServing)}
	if lines := h.lines(historyRequest{Version: historyVersion, Channel: "#sealed", Limit: 10}); len(lines) != 0 {
		t.Errorf("served %d lines for a sealed channel, want 0", len(lines))
	}
}

// TestRecallServingLimit holds the concurrency cap: a node already
// answering as many callers as it will answer turns the next one away
// rather than queueing it.
func TestRecallServingLimit(t *testing.T) {
	h := historyHandler{node: &Node{}, serving: make(chan struct{}, maxRecallServing)}
	for range maxRecallServing {
		h.serving <- struct{}{}
	}
	if lines := served(t, h, nil); lines != 0 {
		t.Errorf("served %d lines while at the serving limit, want none", lines)
	}
	<-h.serving
	// With a slot free the request is answered, which here means
	// reaching the channel lookup rather than being turned away at the
	// door. A node in no channels has nothing to say either way, so
	// what this holds is that the slot was taken and given back.
	served(t, h, nil)
	if len(h.serving) != maxRecallServing-1 {
		t.Errorf("held %d slots after one answer, want %d", len(h.serving), maxRecallServing-1)
	}
}

// TestRecallUnreachable holds that a recall against an address nothing
// answers fails rather than hanging on the caller's context.
func TestRecallUnreachable(t *testing.T) {
	if testing.Short() {
		t.Skip("network test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	alice := newHistoryNode(t, ctx, "alice", WithHistory())
	ach, err := alice.Join(ctx, "#gone", nil)
	if err != nil {
		t.Fatal(err)
	}
	addr := testAddr(t, 9, 1)
	if _, err := ach.Recall(ctx, addr, 10); err == nil {
		t.Error("recall from an unreachable peer succeeded")
	}
}

// A served envelope is signed but does not name a channel, so a peer can
// serve a line somebody really said in one channel as history for
// another. This is that attack, end to end.
func TestCrossChannelReplay(t *testing.T) {
	if testing.Short() {
		t.Skip("network test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	const secret = "the launch code is 1234"

	// Alice says something in #alpha. She is never in #beta.
	alice := newHistoryNode(t, ctx, "alice", WithHistory())
	ach, err := alice.Join(ctx, "#alpha", nil)
	if err != nil {
		t.Fatal(err)
	}
	atick, err := alice.Ticket("#alpha")
	if err != nil {
		t.Fatal(err)
	}
	mallory := newHistoryNode(t, ctx, "mallory", WithHistory())
	alpha, err := mallory.JoinTicket(ctx, atick)
	if err != nil {
		t.Fatal(err)
	}
	_ = ach
	beta, err := mallory.Join(ctx, "#beta", nil)
	if err != nil {
		t.Fatal(err)
	}
	// Said in #alpha, and only in #alpha.
	if err := ach.Say(ctx, secret); err != nil {
		t.Fatal(err)
	}
	// Mallory moves it into what it will serve as #beta's history. A
	// real attacker writes its own server; this is the same bytes.
	deadline := time.Now().Add(10 * time.Second)
	var moved int
	for time.Now().Before(deadline) {
		for _, b := range alpha.recall.recent(10, time.Now()) {
			beta.recall.keep(b, time.Now())
			moved++
		}
		if moved > 0 {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if moved == 0 {
		t.Fatal("nothing in #alpha's reel to move")
	}

	ticket, err := mallory.Ticket("#beta")
	if err != nil {
		t.Fatal(err)
	}
	bob := newHistoryNode(t, ctx, "bob", WithHistory())
	bch, err := bob.JoinTicket(ctx, ticket)
	if err != nil {
		t.Fatal(err)
	}
	in := events(t, bch)
	// The topic is bound into the signature, so alice's #alpha line does
	// not verify as #beta history and is dropped before it is anybody's
	// to read. Nothing replayable should arrive at all.
	// Drain until the deadline rather than looking at one event: a join
	// arrives first, and a test that stops there would pass whether or
	// not the replay was refused.
	deadline = time.Now().Add(5 * time.Second)
	for {
		select {
		case ev := <-in:
			if ev.Kind == Replayed {
				t.Fatalf("VULNERABLE: #beta replayed a line alice said in #alpha: %q; signed by %v (alice=%v), served by %v (mallory=%v)",
					ev.Text, ev.From.ID.Short(), alice.ID().Short(), ev.Via.ID.Short(), mallory.ID().Short())
			}
		case <-time.After(time.Until(deadline)):
			return
		}
	}
}

// TestRecallSaysWhatItWouldNotReplay checks that lines a peer served and
// this node refused are reported rather than quietly missing. A reader
// shown twelve lines cannot tell that fifty were offered, so a peer
// serving junk is indistinguishable from a peer that had little to say -
// and those want different responses from whoever is reading.
func TestRecallSaysWhatItWouldNotReplay(t *testing.T) {
	if testing.Short() {
		t.Skip("network test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	alice := newHistoryNode(t, ctx, "alice", WithHistory())
	ach, err := alice.Join(ctx, "#drop", nil)
	if err != nil {
		t.Fatal(err)
	}
	// One line that verifies here, and three that do not: same bytes, a
	// different channel's signature. What they are wrong about does not
	// matter, only that this node will not replay them.
	sk := alice.secret()
	now := time.Now()
	ach.recall.keep(mustSign(t, sk, ach.domain(), kindMessage, 1, "the one good line"), now)
	elsewhere := [32]byte{'s', 'o', 'm', 'e', 'w', 'h', 'e', 'r', 'e'}
	for i := range 3 {
		ach.recall.keep(mustSign(t, sk, elsewhere, kindMessage, uint64(2+i), "said in another channel"), now)
	}

	ticket, err := alice.Ticket("#drop")
	if err != nil {
		t.Fatal(err)
	}
	bob := newHistoryNode(t, ctx, "bob", WithHistory())
	bch, err := bob.JoinTicket(ctx, ticket)
	if err != nil {
		t.Fatal(err)
	}
	in := events(t, bch)

	// Both are wanted: the good line replayed, and one refusal saying
	// how many were not. Drain until both arrive or the deadline, since
	// a join arrives first and the order of the two is not the claim.
	var replayed, refused int
	var reason string
	deadline := time.Now().Add(15 * time.Second)
	for replayed == 0 || refused == 0 {
		select {
		case ev := <-in:
			switch ev.Kind {
			case Replayed:
				replayed++
			case Refused:
				refused++
				reason = ev.Text
				if ev.From.ID != alice.ID() {
					t.Errorf("the refusal names %v, want the peer that served it (%v)", ev.From.ID.Short(), alice.ID().Short())
				}
			}
		case <-time.After(time.Until(deadline)):
			t.Fatalf("replayed %d lines and heard %d refusals; want one of each", replayed, refused)
		}
	}
	if !strings.Contains(reason, "3 of 4") {
		t.Errorf("refusal says %q; want it to account for 3 of the 4 lines served", reason)
	}
	if replayed != 1 {
		t.Errorf("replayed %d lines, want the one that verifies", replayed)
	}
}

// Recall is a direct dial, not gossip. A node that cannot hear a channel
// can still be told what was said in it, which is why a partitioned
// swarm is not automatically a swarm with no history: the two nodes here
// share a channel name and nothing else, and the lines cross anyway.
func TestRecallCrossesAGossipPartition(t *testing.T) {
	if testing.Short() {
		t.Skip("network test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	alice := newHistoryNode(t, ctx, "alice", WithHistory())
	ach, err := alice.Join(ctx, "#split", nil)
	if err != nil {
		t.Fatal(err)
	}
	// Bob joins the same channel with no peers at all, so there is no
	// path by which the two gossip meshes could ever meet.
	bob := newHistoryNode(t, ctx, "bob", WithHistory())
	bch, err := bob.Join(ctx, "#split", nil)
	if err != nil {
		t.Fatal(err)
	}
	in := events(t, bch)

	said := []string{"one", "two", "three"}
	for _, text := range said {
		if err := ach.Say(ctx, text); err != nil {
			t.Fatal(err)
		}
	}

	// The control: without this, a test that sees the lines arrive
	// proves nothing, because the two nodes might simply have found
	// each other. Nothing alice says reaches bob.
	silent := func(what string) {
		t.Helper()
		select {
		case ev := <-in:
			if ev.Kind == Message {
				t.Fatalf("%s: bob heard %q across the partition", what, ev.Text)
			}
		case <-time.After(2 * time.Second):
		}
	}
	silent("before recall")

	// Bob is dialable and keeps nothing, which is what makes the
	// silence above a gossip partition rather than two nodes that
	// cannot reach each other at all.
	if _, err := ach.Recall(ctx, bob.Addr(), 10); !errors.Is(err, ErrNoHistory) {
		t.Fatalf("recall from bob = %v, want %v", err, ErrNoHistory)
	}
	if _, err := bch.Recall(ctx, alice.Addr(), 10); err != nil {
		t.Fatalf("recall across the partition: %v", err)
	}
	for i := range said {
		ev := await(t, ctx, in, ofKind(Replayed), "replayed line")
		if ev.Text != said[i] {
			t.Errorf("replayed line %d = %q, want %q", i, ev.Text, said[i])
		}
		if ev.Via.ID != alice.ID() {
			t.Errorf("replayed line %d was served by %v, want %v", i, ev.Via.ID.Short(), alice.ID().Short())
		}
	}

	// A recall is not a join. Answering one leaves the two nodes as
	// partitioned as it found them, so the line alice says next is
	// still not heard.
	if err := ach.Say(ctx, "after"); err != nil {
		t.Fatal(err)
	}
	silent("after recall")
}

// A testStream is a recall stream that holds one request and records the
// answer, or hands each write to write when it is set.
type testStream struct {
	*bytes.Reader
	out   bytes.Buffer
	write func([]byte) (int, error)
}

func (s *testStream) Write(b []byte) (int, error) {
	if s.write != nil {
		return s.write(b)
	}
	return s.out.Write(b)
}

func (s *testStream) CloseWrite() error           { return nil }
func (s *testStream) SetDeadline(time.Time) error { return nil }

// newTestStream returns a stream carrying a well-formed request.
func newTestStream(t *testing.T, write func([]byte) (int, error)) *testStream {
	t.Helper()
	req, err := postcard.Marshal(historyRequest{Version: historyVersion, Channel: "#busy", Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	return &testStream{Reader: bytes.NewReader(req), write: write}
}

// served runs one exchange against h and returns how many lines the
// answer held.
func served(t *testing.T, h historyHandler, write func([]byte) (int, error)) int {
	t.Helper()
	s := newTestStream(t, write)
	if err := h.serve(s); err != nil {
		t.Fatal(err)
	}
	var resp historyResponse
	if err := postcard.Unmarshal(s.out.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	return len(resp.Lines)
}

// TestRecallHoldsTheSlotWhileWriting checks that the serving allowance
// covers the write. The write is the part of an answer that waits on
// the caller, so a slot given back before it bounded nothing: a caller
// that asked and never read held a stream each, however many it opened.
func TestRecallHoldsTheSlotWhileWriting(t *testing.T) {
	h := historyHandler{node: &Node{}, serving: make(chan struct{}, maxRecallServing)}
	writing, release := make(chan struct{}), make(chan struct{})
	s := newTestStream(t, func(b []byte) (int, error) {
		close(writing)
		<-release
		return len(b), nil
	})
	done := make(chan error)
	go func() { done <- h.serve(s) }()
	<-writing
	if got := len(h.serving); got != 1 {
		t.Errorf("%d slots held while the answer is being written, want 1", got)
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if got := len(h.serving); got != 0 {
		t.Errorf("%d slots held after the answer, want 0", got)
	}
}

// TestRecallHonorsQuiet checks that a sender this node has muted is not
// brought back by history. WithQuiet is this node's own decision not to
// hear someone, and a replay is still hearing them.
func TestRecallHonorsQuiet(t *testing.T) {
	if testing.Short() {
		t.Skip("network test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	mallory, err := key.GenerateSecretKey()
	if err != nil {
		t.Fatal(err)
	}
	alice := newHistoryNode(t, ctx, "alice", WithHistory())
	ach, err := alice.Join(ctx, "#muted", nil)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	ach.recall.keep(mustSign(t, mallory, ach.domain(), kindMessage, 1, "from mallory"), now)
	ach.recall.keep(mustSign(t, alice.secret(), ach.domain(), kindMessage, 1, "from alice"), now)
	ticket, err := alice.Ticket("#muted")
	if err != nil {
		t.Fatal(err)
	}

	muted := mallory.Public().EndpointID()
	bob := newHistoryNode(t, ctx, "bob", WithQuiet(func(id key.EndpointID) bool { return id == muted }))
	bch, err := bob.JoinTicket(ctx, ticket)
	if err != nil {
		t.Fatal(err)
	}
	in := events(t, bch)
	n, err := bch.Recall(ctx, ticket.Peers[0], 10)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Errorf("replayed %d lines, want only alice's", n)
	}
	if ev := await(t, ctx, in, ofKind(Replayed), "alice's line"); ev.Text != "from alice" {
		t.Errorf("replayed %q, want alice's line", ev.Text)
	}
	// Nothing further: neither mallory's line nor a refusal blaming
	// alice for serving it.
	deadline := time.After(time.Second)
	for {
		select {
		case ev := <-in:
			if ev.Kind == Replayed || ev.Kind == Refused {
				t.Errorf("unexpected %v event: %q", ev.Kind, ev.Text)
			}
		case <-deadline:
			return
		}
	}
}
