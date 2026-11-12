package irciroh

import (
	"testing"
	"time"

	"github.com/tmc/go-iroh/key"
)

// sealedFixture returns a channel sealed under founder, with each of ids
// already on the roster, and a clock to hand to apply.
func sealedFixture(founder key.EndpointID, ids ...key.EndpointID) (*Channel, time.Time) {
	c := &Channel{
		node:    &Node{},
		members: make(map[key.EndpointID]*member),
		lastSeq: make(seqSet),
		spent:   make(budgets),
	}
	c.seal = &sealed{ch: c, founder: founder}
	now := time.Now()
	for _, id := range append([]key.EndpointID{founder}, ids...) {
		c.touch(id, "", now)
	}
	return c, now
}

func TestGrantRoundTrip(t *testing.T) {
	for _, r := range []Rank{Ordinary, Voiced, Operator} {
		g := grant{target: testID(t), rank: r}
		got, ok := parseGrant(g.String())
		if !ok || got != g {
			t.Errorf("parseGrant(%q) = %v, %v; want %v", g, got, ok, g)
		}
	}
	for _, bad := range []string{"", "voiced", "queen " + testID(t).Z32(), "voiced not-an-id", "voiced"} {
		if _, ok := parseGrant(bad); ok {
			t.Errorf("parseGrant(%q) accepted", bad)
		}
	}
}

// TestRankAuthority covers who may change whose standing. Only the
// founder moves a member into or out of Operator, so operators can
// neither promote past the founder's reach nor depose one another; an
// ordinary member's grant is worth nothing at all.
func TestRankAuthority(t *testing.T) {
	tests := []struct {
		name    string
		founder bool // the grant comes from the founder itself
		setter  Rank // otherwise, the granter's standing
		cur     Rank // the target's standing before the grant
		give    Rank
		want    Rank
	}{
		{name: "founder voices", founder: true, give: Voiced, want: Voiced},
		{name: "founder ops", founder: true, give: Operator, want: Operator},
		{name: "operator voices", setter: Operator, give: Voiced, want: Voiced},
		{name: "operator devoices", setter: Operator, cur: Voiced, give: Ordinary, want: Ordinary},
		{name: "operator cannot op", setter: Operator, give: Operator, want: Ordinary},
		{name: "ordinary member grants nothing", setter: Ordinary, give: Voiced, want: Ordinary},
		{name: "voiced member grants nothing", setter: Voiced, give: Voiced, want: Ordinary},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			founder, setter, target := testID(t), testID(t), testID(t)
			c, now := sealedFixture(founder, setter, target)
			c.members[setter].rank = tt.setter
			c.members[target].rank = tt.cur
			if tt.founder {
				setter = founder
			}
			c.apply(kindRank, "", grant{target: target, rank: tt.give}.String(), setter, now, now, true)
			if got := c.rank(target); got != tt.want {
				t.Errorf("rank = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestOperatorCannotTouchOperator covers the one-level authority tree: an
// operator is the founder's appointee, so only the founder unmakes it.
func TestOperatorCannotTouchOperator(t *testing.T) {
	founder, op, other := testID(t), testID(t), testID(t)
	c, now := sealedFixture(founder, op, other)
	c.members[op].rank = Operator
	c.members[other].rank = Operator

	for _, give := range []Rank{Ordinary, Voiced} {
		c.apply(kindRank, "", grant{target: other, rank: give}.String(), op, now, now, true)
		if got := c.rank(other); got != Operator {
			t.Errorf("operator demoted a peer to %v", got)
		}
	}
	c.apply(kindRank, "", grant{target: other, rank: Ordinary}.String(), founder, now, now, true)
	if got := c.rank(other); got != Ordinary {
		t.Errorf("the founder's revocation left rank %v, want ordinary", got)
	}
}

// TestFounderRankIsNotAGrant covers that the founder's standing is a fact
// about the topic derivation, not something the roster records, so no
// grant can take it away.
func TestFounderRankIsNotAGrant(t *testing.T) {
	founder, op := testID(t), testID(t)
	c, now := sealedFixture(founder, op)
	c.members[op].rank = Operator
	for _, from := range []key.EndpointID{op, founder} {
		c.apply(kindRank, "", grant{target: founder, rank: Ordinary}.String(), from, now, now, true)
		if got := c.rank(founder); got != Operator {
			t.Errorf("founder demoted to %v", got)
		}
	}
}

// TestGrantToStrangerIsDropped covers that a rank lives on a roster entry.
// Remembering a grant for an endpoint nobody has seen would be an
// unbounded table fed by anyone allowed to speak.
func TestGrantToStrangerIsDropped(t *testing.T) {
	founder := testID(t)
	c, now := sealedFixture(founder)
	stranger := testID(t)
	c.apply(kindRank, "", grant{target: stranger, rank: Operator}.String(), founder, now, now, true)
	if _, ok := c.members[stranger]; ok {
		t.Error("a grant added a member to the roster")
	}
	if got := c.rank(stranger); got != Ordinary {
		t.Errorf("rank = %v, want ordinary", got)
	}
}

// TestModerationSilencesTheUnvoiced covers +m. An unvoiced member is
// dropped and a voiced one is heard, and either way the channel still
// learns the member is there: being quiet is not being absent.
func TestModerationSilencesTheUnvoiced(t *testing.T) {
	founder, op, quiet, loud := testID(t), testID(t), testID(t), testID(t)
	c, now := sealedFixture(founder, op, quiet, loud)
	c.members[op].rank = Operator
	c.members[loud].rank = Voiced

	if out := c.apply(kindMode, "", modeModerated, op, now, now, true); len(out) != 1 || out[0].Kind != ModeChanged {
		t.Fatalf("an operator's +m produced %v", out)
	}
	if !c.moderated {
		t.Fatal("channel is not moderated")
	}
	for _, tt := range []struct {
		name string
		from key.EndpointID
		want bool
	}{
		{"unvoiced", quiet, false},
		{"voiced", loud, true},
		{"operator", op, true},
		{"founder", founder, true},
	} {
		out := c.apply(kindMessage, "", "hello", tt.from, now, now, true)
		heard := len(out) > 0 && out[len(out)-1].Kind == Message
		if heard != tt.want {
			t.Errorf("%s member heard=%v, want %v (%v)", tt.name, heard, tt.want, out)
		}
	}

	// A newcomer's first word is dropped, but the channel still sees it
	// join.
	newcomer := testID(t)
	out := c.apply(kindMessage, "nick", "hello", newcomer, now, now, true)
	if len(out) != 1 || out[0].Kind != Joined {
		t.Errorf("a silenced newcomer produced %v, want one Joined", out)
	}
}

// TestModeNeedsAnOperator covers that moderation is not something any
// member can turn on for everyone else.
func TestModeNeedsAnOperator(t *testing.T) {
	founder, voiced := testID(t), testID(t)
	c, now := sealedFixture(founder, voiced)
	c.members[voiced].rank = Voiced
	for _, text := range []string{modeModerated, "+m", "garbage"} {
		c.apply(kindMode, "", text, voiced, now, now, true)
		if c.moderated {
			t.Fatalf("a voiced member set %q", text)
		}
	}
	c.apply(kindMode, "", modeModerated, founder, now, now, true)
	if !c.moderated {
		t.Fatal("the founder could not moderate")
	}
	c.apply(kindMode, "", modeOpen, founder, now, now, true)
	if c.moderated {
		t.Fatal("the founder could not reopen")
	}
}

// TestPublicChannelHasNoAuthority covers the honest half of the design. A
// public channel's topic derives from its name, so there is no founder to
// check a claim against and a rank envelope is worth nothing; believing
// one would let the first speaker moderate everyone else.
func TestPublicChannelHasNoAuthority(t *testing.T) {
	c := &Channel{
		node:    &Node{},
		members: make(map[key.EndpointID]*member),
		lastSeq: make(seqSet),
		spent:   make(budgets),
	}
	now := time.Now()
	claimant, victim := testID(t), testID(t)
	c.touch(claimant, "", now)
	c.touch(victim, "", now)

	c.apply(kindRank, "", grant{target: claimant, rank: Operator}.String(), claimant, now, now, true)
	if got := c.rank(claimant); got != Ordinary {
		t.Errorf("a public channel granted rank %v", got)
	}
	c.apply(kindMode, "", modeModerated, claimant, now, now, true)
	if c.Moderated() {
		t.Error("a public channel was moderated")
	}
	out := c.apply(kindMessage, "", "hello", victim, now, now, true)
	if len(out) == 0 || out[len(out)-1].Kind != Message {
		t.Errorf("a public channel silenced a member: %v", out)
	}
}

// TestRankConvergesUnderReordering covers two operators granting
// different standings at once. Gossip delivers the pair in whatever
// order each member happens to see, so the two members must still agree
// afterwards.
func TestRankConvergesUnderReordering(t *testing.T) {
	founder, op1, op2, target := testID(t), testID(t), testID(t), testID(t)
	first, second := grant{target: target, rank: Voiced}.String(), grant{target: target, rank: Ordinary}.String()

	rank := func(order ...key.EndpointID) Rank {
		c, now := sealedFixture(founder, op1, op2, target)
		c.members[op1].rank = Operator
		c.members[op2].rank = Operator
		at := map[key.EndpointID]time.Time{op1: now, op2: now}
		text := map[key.EndpointID]string{op1: first, op2: second}
		for _, from := range order {
			c.apply(kindRank, "", text[from], from, at[from], now, true)
		}
		return c.members[target].rank
	}
	if a, b := rank(op1, op2), rank(op2, op1); a != b {
		t.Errorf("rank = %v one way and %v the other; grants did not converge", a, b)
	}

	// A grant that lost the tie stays lost however late it arrives, so
	// a replayed envelope cannot undo the one that won.
	c, now := sealedFixture(founder, op1, op2, target)
	c.members[op1].rank = Operator
	c.members[op2].rank = Operator
	c.apply(kindRank, "", first, op1, now.Add(time.Second), now, true)
	c.apply(kindRank, "", second, op2, now, now, true)
	if got := c.members[target].rank; got != Voiced {
		t.Errorf("rank = %v after a stale grant, want voiced", got)
	}
}

// TestModerationSilencesTheTopic covers that +m reaches the topic. An
// unvoiced member that could still rewrite the topic would be silenced
// in name only.
func TestModerationSilencesTheTopic(t *testing.T) {
	founder, quiet := testID(t), testID(t)
	c, now := sealedFixture(founder, quiet)
	c.moderated = true

	if out := c.apply(kindTopic, "", "mine now", quiet, now, now, true); len(out) != 0 {
		t.Errorf("an unvoiced member set the topic: %v", out)
	}
	if c.set {
		t.Errorf("topic = %q, want none", c.subject)
	}
	// The same text relayed on a presence ping is no different.
	if out := c.apply(kindPing, "", topicMark+"mine now", quiet, now, now, true); len(out) != 0 {
		t.Errorf("an unvoiced member relayed a topic: %v", out)
	}
	if out := c.apply(kindTopic, "", "ours", founder, now, now, true); len(out) != 1 || out[0].Kind != TopicChanged {
		t.Fatalf("the founder's topic produced %v", out)
	}
}
