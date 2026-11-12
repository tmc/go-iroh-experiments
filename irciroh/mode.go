package irciroh

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/tmc/go-iroh/key"
)

// Moderation is a sealed channel's business. A public channel derives its
// topic from its name alone, so it has no founder and nothing to check a
// claim of authority against: a node that announced itself an operator
// there would be believed exactly as much as one that announced itself
// the queen. The mode and rank envelopes below are therefore ignored on a
// public channel rather than honored on trust, and [WithQuiet] is what a
// node on one has instead.
//
// On a sealed channel the founder's endpoint is in the topic derivation
// and MLS authenticates every sender, so "the founder said so" is a fact a
// member can check for itself. A rank is that: a statement from a known
// authority, which every compliant member honors. It is weaker than the
// roster, which is cryptographic - a member removed from the group cannot
// read what is said next no matter what software it runs - and the
// difference is deliberate. Honoring a rank is enforced by each member's
// own code, so a member running modified code can speak into a moderated
// channel; what answers that is [Channel.Kick], which is a real removal.

var (
	// ErrNotOperator is returned for a mode change this node lacks the
	// standing to make.
	ErrNotOperator = errors.New("not an operator of that channel")
	// ErrNotMember is returned when the endpoint named by a grant is not
	// on the channel.
	ErrNotMember = errors.New("not a member of that channel")
	// ErrModerated is returned by [Channel.Say] and [Channel.Notice] on a
	// moderated channel where this node has no voice.
	ErrModerated = errors.New("channel is moderated and this node has no voice")
	// ErrFounderRank is returned by [Channel.Grant] for a grant naming
	// the founder. The founder's standing follows from the channel's
	// topic derivation rather than from the roster, so there is nothing
	// there for a grant to change - not even by the founder itself.
	ErrFounderRank = errors.New("the founder's standing is not a grant")
)

// A Rank is a member's standing on a sealed channel. The zero value,
// Ordinary, is what every member holds until the founder says otherwise.
//
// The ranks form a ladder rather than IRC's independent flags: an
// operator is voiced by definition, so there is no state where a member
// may moderate a channel but not speak on it.
type Rank uint8

const (
	// Ordinary is a member with no standing. It may speak on an open
	// channel and not on a moderated one.
	Ordinary Rank = iota
	// Voiced is a member that may speak even while the channel is
	// moderated.
	Voiced
	// Operator is a member that may voice and devoice others and turn
	// moderation on and off. It cannot grant or revoke Operator, and it
	// cannot kick: both are the founder's, because both need a commit.
	Operator
)

// String returns the rank's name, which is also its wire form.
func (r Rank) String() string {
	switch r {
	case Ordinary:
		return "ordinary"
	case Voiced:
		return "voiced"
	case Operator:
		return "operator"
	}
	return fmt.Sprintf("Rank(%d)", uint8(r))
}

// parseRank parses a rank name.
func parseRank(s string) (Rank, bool) {
	for _, r := range []Rank{Ordinary, Voiced, Operator} {
		if s == r.String() {
			return r, true
		}
	}
	return 0, false
}

// A grant is the payload of a kindRank envelope: the standing a member is
// to hold, written out in full rather than as a change to apply. An
// absolute statement is idempotent and does not depend on having seen the
// ones before it, which a "+o" would.
type grant struct {
	target key.EndpointID
	rank   Rank
}

// String returns the wire text of g: the rank name, a space, and the
// target endpoint in z-base-32.
func (g grant) String() string { return g.rank.String() + " " + g.target.Z32() }

// parseGrant parses the text of a kindRank envelope.
func parseGrant(text string) (grant, bool) {
	name, z32, ok := strings.Cut(text, " ")
	if !ok {
		return grant{}, false
	}
	r, ok := parseRank(name)
	if !ok {
		return grant{}, false
	}
	id, err := key.ParseEndpointIDZ32(z32)
	if err != nil {
		return grant{}, false
	}
	return grant{target: id, rank: r}, true
}

// Wire text of a kindMode envelope.
const (
	modeModerated = "moderated"
	modeOpen      = "open"
)

// Rank returns a member's standing. It is Ordinary for every member of a
// public channel, which has no authority to grant anything, and Operator
// for a sealed channel's founder, whose standing is not a grant and cannot
// be taken away.
func (c *Channel) Rank(id key.EndpointID) Rank {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.rank(id)
}

// rank returns a member's standing. The caller holds c.mu.
func (c *Channel) rank(id key.EndpointID) Rank {
	if c.seal == nil {
		return Ordinary
	}
	if id == c.seal.founder {
		return Operator
	}
	if m := c.members[id]; m != nil {
		return m.rank
	}
	return Ordinary
}

// Moderated reports whether the channel is moderated, in which case only
// voiced members and operators are heard. A public channel is never
// moderated.
func (c *Channel) Moderated() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.moderated
}

// Moderate turns moderation on or off. It is the founder's and its
// operators' to set; ErrNotSealed is returned for a public channel and
// ErrNotOperator for a sealed one where this node does not have the
// standing.
func (c *Channel) Moderate(ctx context.Context, on bool) error {
	if c.seal == nil {
		return ErrNotSealed
	}
	c.mu.Lock()
	mine := c.rank(c.node.ID())
	c.mu.Unlock()
	if mine != Operator {
		return ErrNotOperator
	}
	text := modeOpen
	if on {
		text = modeModerated
	}
	at, err := c.broadcast(ctx, kindMode, text)
	if err != nil {
		return err
	}
	// A node never receives its own gossip back, so what it said has to
	// be applied here or it would be the only member that did not hear
	// it, and by the rule [Channel.applyMode] applies it by, or it
	// could be the only member that kept it. [Channel.SetTopic] does
	// the same.
	self := c.node.ID()
	c.mu.Lock()
	if newer(at, c.modeAt, self, c.modeBy) {
		c.moderated, c.modeAt, c.modeBy = on, at, self
	}
	c.mu.Unlock()
	return nil
}

// Grant sets a member's standing. Only the founder may grant or revoke
// [Operator]; an operator may voice and devoice any member that is not
// itself an operator. ErrNotSealed is returned for a public channel,
// ErrNotFounder or ErrNotOperator when this node lacks the standing,
// ErrFounderRank for a grant naming the founder, and ErrNotMember when
// id is not on the channel.
//
// A grant is not retroactive and not durable against a rejoin: it names an
// endpoint on this channel now. The founder regrants after a member
// rejoins with a fresh identity, which is the same place [Channel.Kick]
// draws its line. It regrants, too, after removing a member it had not
// heard from and letting it back in: the removal ended the membership
// the rank was on, for every member including the removed one.
func (c *Channel) Grant(ctx context.Context, id key.EndpointID, r Rank) error {
	if c.seal == nil {
		return ErrNotSealed
	}
	if r > Operator {
		return fmt.Errorf("grant %v: unknown rank", uint8(r))
	}
	c.mu.Lock()
	mine, theirs := c.rank(c.node.ID()), c.rank(id)
	known := c.members[id] != nil
	founder := id == c.seal.founder
	c.mu.Unlock()

	switch {
	case founder:
		return ErrFounderRank
	case !known:
		return ErrNotMember
	case mine != Operator:
		return ErrNotOperator
	case (r == Operator || theirs == Operator) && !c.seal.isFounder():
		return ErrNotFounder
	}
	at, err := c.broadcast(ctx, kindRank, grant{target: id, rank: r}.String())
	if err != nil {
		return err
	}
	self := c.node.ID()
	c.mu.Lock()
	if m := c.members[id]; m != nil && newer(at, m.rankAt, self, m.rankBy) {
		m.rank, m.rankAt, m.rankBy = r, at, self
	}
	c.mu.Unlock()
	return nil
}

// applyMode applies a kindMode envelope. The caller holds c.mu.
func (c *Channel) applyMode(text string, from key.EndpointID, at time.Time) []Event {
	if c.seal == nil || c.rank(from) != Operator {
		return nil
	}
	var on bool
	switch text {
	case modeModerated:
		on = true
	case modeOpen:
	default:
		return nil
	}
	if !newer(at, c.modeAt, from, c.modeBy) {
		return nil
	}
	c.modeAt, c.modeBy = at, from
	if c.moderated == on {
		return nil
	}
	c.moderated = on
	return []Event{{Kind: ModeChanged, From: c.snapshot(from), Text: text, Time: at}}
}

// applyRank applies a kindRank envelope. The caller holds c.mu.
func (c *Channel) applyRank(text string, from key.EndpointID, at time.Time) []Event {
	if c.seal == nil {
		return nil
	}
	g, ok := parseGrant(text)
	if !ok {
		return nil
	}
	m := c.members[g.target]
	if m == nil || g.target == c.seal.founder {
		// A rank lives on a member of the roster, so a grant to an
		// endpoint this node has not seen is dropped rather than
		// remembered: remembering it would be an unbounded table fed
		// by anyone who may speak. The founder regrants if the order
		// of arrival lost one.
		return nil
	}
	// Only the founder's word moves anyone into or out of Operator, so
	// operators cannot promote each other past the founder's reach or
	// depose one another.
	if c.rank(from) != Operator {
		return nil
	}
	if (g.rank == Operator || m.rank == Operator) && from != c.seal.founder {
		return nil
	}
	if !newer(at, m.rankAt, from, m.rankBy) {
		return nil
	}
	m.rankAt, m.rankBy = at, from
	if m.rank == g.rank {
		return nil
	}
	old := m.rank
	m.rank = g.rank
	return []Event{{Kind: RankChanged, From: c.snapshot(g.target), By: c.snapshot(from), Text: g.rank.String(), Old: old.String(), Time: at}}
}

// silenced reports whether a moderated channel drops what from says. The
// caller holds c.mu.
func (c *Channel) silenced(from key.EndpointID) bool {
	return c.moderated && c.rank(from) == Ordinary
}

// mayspeak reports the error, if any, that moderation makes of this node
// saying something.
func (c *Channel) mayspeak() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.silenced(c.node.ID()) {
		return ErrModerated
	}
	return nil
}
