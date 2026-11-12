package irciroh

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"iter"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/tmc/go-iroh/gossip"
	"github.com/tmc/go-iroh/key"
	"github.com/tmc/go-iroh/netaddr"
)

// Presence timing. They are variables so tests can shorten them.
var (
	// presenceInterval is how often a member broadcasts a ping.
	presenceInterval = 30 * time.Second

	// rotateInterval is how often a member of a sealed channel
	// proposes new keys for its own leaf, and how often the founder
	// commits what members have proposed. Recovery requires delivery and
	// an accepted update; this interval is a retry schedule, not a bound
	// on exposure. The founder retains its signing key.
	rotateInterval = 15 * time.Minute
	// presenceTimeout is how long a member may go unheard before it is
	// dropped from the channel.
	presenceTimeout = 90 * time.Second
	// presenceSweep is how often the member table is checked for timeouts.
	presenceSweep = 10 * time.Second
)

// topicMark prefixes the channel topic carried by a presence ping, so a
// joiner learns the topic without a request and reply.
const topicMark = "\x01"

// ErrChannelName is returned for a channel name that is not a legal IRC
// channel name.
var ErrChannelName = errors.New("invalid channel name")

// EventKind classifies a channel event.
type EventKind uint8

const (
	// Joined reports a member appearing on the channel.
	Joined EventKind = iota
	// Parted reports a member leaving. Text is the member's parting
	// message, or "timeout" when presence expired.
	Parted
	// Message reports channel text.
	Message
	// Notice reports a channel notice.
	Notice
	// TopicChanged reports a new channel topic in Text.
	TopicChanged
	// NickChanged reports a member's new nick in Text and its previous
	// nick in Old.
	NickChanged
	// Lagged reports that a slow reader missed one or more events.
	Lagged
	// Refused reports that this node turned something away, with the
	// reason in Text. From names the endpoint when the refusal was of
	// an authenticated dial - a sealed channel's door, or a peer's
	// answer to a recall - and is zero when the refusal was of gossip,
	// which nobody signs. A rate limit refuses on either kind of
	// channel, so this is not a sealed channel's event.
	Refused
	// ModeChanged reports that a channel mode was set, with the mode in
	// Text and the operator that set it in From. See [Channel.Moderate].
	ModeChanged
	// RankChanged reports a member's new standing in Text and its
	// previous standing in Old. From is the member whose rank changed,
	// not the operator that changed it.
	RankChanged
	// Replayed reports a line a peer served as history rather than one
	// this node heard said: From is the key that signed it, Via is the
	// peer that handed it over, and Was is what it was said as. See
	// [Channel.Recall].
	Replayed
	// Split reports that more than one member expired in a single
	// presence sweep, with how many and what this node has left in
	// Text. It carries no From: like [Lagged], it is this node saying
	// something about itself rather than about anybody on the channel.
	Split
)

// String returns the event kind's name.
func (k EventKind) String() string {
	switch k {
	case Joined:
		return "joined"
	case Parted:
		return "parted"
	case Message:
		return "message"
	case Notice:
		return "notice"
	case TopicChanged:
		return "topic"
	case NickChanged:
		return "nick"
	case Lagged:
		return "lagged"
	case Refused:
		return "refused"
	case ModeChanged:
		return "mode"
	case RankChanged:
		return "rank"
	case Replayed:
		return "replayed"
	case Split:
		return "split"
	}
	return fmt.Sprintf("EventKind(%d)", uint8(k))
}

// An Event is one thing that happened on a channel, or one private message.
type Event struct {
	Kind EventKind
	From Member
	// Text is the message, notice, topic, parting reason, or new nick.
	Text string
	// Old is the previous nick, for NickChanged, or the previous rank,
	// for RankChanged.
	Old string
	// Via is the member that served this event as history, for
	// Replayed. It is zero on everything this node heard for itself,
	// which is every other kind.
	Via Member
	// Was is what a Replayed line was said as: Message or Notice. It
	// is zero and meaningless on every other kind.
	Was EventKind
	// By is who made the statement, for RankChanged, where From is the
	// member it is about rather than the member who said it. A rank is
	// signed policy and its whole worth is that a member can check who
	// stands behind it, so reporting the change without the authority
	// would throw away the part that makes it worth honoring.
	By Member
	// Time is the sender's clock reading.
	Time time.Time
}

// A Member is one participant seen on a channel.
type Member struct {
	ID   key.EndpointID
	Nick string
	Seen time.Time
	// Rank is the member's standing on a sealed channel. See [Rank].
	Rank Rank
}

// member is the mutable form of a Member.
type member struct {
	nick string
	seen time.Time
	rank Rank
	// rankAt and rankBy are the time and author of the statement that
	// last set rank, which is what makes two members that see the same
	// grants in opposite orders end up agreeing. See newer.
	rankAt time.Time
	rankBy key.EndpointID
}

// A Channel is one joined chat channel: a gossip topic, a member table, and
// a topic. Obtain one from [Node.Join], [Node.JoinTicket] or [Node.Found].
//
// A channel is public or sealed. On a public channel the gossip payload
// is a signed envelope that every member of the topic can read, which is
// IRC's model. On a sealed channel it is an MLS message that only the
// members of the group can read; see [Node.Found].
type Channel struct {
	node   *Node
	name   string
	secret []byte
	topic  *gossip.Topic
	quit   chan struct{}
	// seal is non-nil on a sealed channel, whose gossip payloads are
	// MLS messages rather than signed envelopes. See sealed.
	seal *sealed
	// resyncing serializes rejoins, so that a burst of messages from an
	// epoch this node cannot read produces one exchange with the
	// founder and not one per message.
	resyncing sync.Mutex
	started   atomic.Bool
	// sending holds a public envelope's sequence number and its
	// broadcast together, so that this node's envelopes leave in the
	// order they were numbered. A Say racing a ping would otherwise put
	// the higher number on the wire first.
	sending sync.Mutex

	emu    sync.Mutex
	closed bool
	events chan Event

	// recall is the recent speech this node will serve to a joiner,
	// and is empty unless the node was given [WithHistory]. It has its
	// own lock: it is written on the receive path and read by whatever
	// goroutine is answering a stranger, and neither should wait on
	// the channel's own state. See history.go.
	recall reel

	mu      sync.Mutex
	members map[key.EndpointID]*member
	order   []key.EndpointID
	lastSeq seqSet
	// spent is what each sender has left to say. See limit.go.
	spent budgets
	// unverified counts envelopes received on this channel whose
	// signatures or contents did not verify, and holds the refusals
	// not yet reported. It has no sender because an unverified
	// envelope has no trustworthy attribution.
	unverified    uint64
	unverifiedRun run
	// unverifiedNear is how far away the closest of the envelopes in
	// unverifiedRun was, which is the one thing about them worth
	// saying once their attribution is worthless.
	unverifiedNear nearest
	// pinged is when this node last announced itself, which is what
	// holds its own presence to a rate its receivers can afford. See
	// pingSoon.
	pinged time.Time
	// unheard is when each neighbor this node has not heard from was
	// found so, or last rejoined for it. See overdue.
	unheard map[key.EndpointID]time.Time
	subject string
	by      key.EndpointID
	at      time.Time
	set     bool
	// firm reports that subject came from a topic envelope rather than
	// from a presence ping, which relays text but not authorship.
	firm bool
	// moderated reports that only voiced members are heard. See mode.go.
	moderated bool
	// modeAt and modeBy are the time and author of the statement that
	// last set moderated. See newer.
	modeAt time.Time
	modeBy key.EndpointID
}

// checkChannel validates an IRC channel name and returns its folded form.
//
// Beyond what IRC forbids - a space, a comma, a control character - a
// name may not hold a slash or a backslash, or be "." or ".." after its
// prefix, so that it is always safe as a single path element: the
// bridge files each channel's log under its name.
func checkChannel(name string) (string, error) {
	if len(name) < 2 || name[0] != '#' {
		return "", fmt.Errorf("channel %q must start with #: %w", name, ErrChannelName)
	}
	if len(name) > 50 {
		return "", fmt.Errorf("channel %q is too long: %w", name, ErrChannelName)
	}
	for _, r := range name {
		if r == ' ' || r == ',' || r == '/' || r == '\\' || control(r) {
			return "", fmt.Errorf("channel %q contains %q: %w", name, r, ErrChannelName)
		}
	}
	if rest := name[1:]; rest == "." || rest == ".." {
		return "", fmt.Errorf("channel %q is not a name: %w", name, ErrChannelName)
	}
	return Fold(name), nil
}

// Name returns the channel's folded name, including its # prefix.
func (c *Channel) Name() string { return c.name }

// Say broadcasts text to the channel.
func (c *Channel) Say(ctx context.Context, text string) error {
	if err := c.mayspeak(); err != nil {
		return err
	}
	_, err := c.broadcast(ctx, kindMessage, text)
	return err
}

// Notice broadcasts a notice to the channel. IRC clients do not reply
// automatically to a notice.
func (c *Channel) Notice(ctx context.Context, text string) error {
	if err := c.mayspeak(); err != nil {
		return err
	}
	_, err := c.broadcast(ctx, kindNotice, text)
	return err
}

// SetTopic broadcasts a new channel topic. The last writer wins, ordered by
// the senders' clocks and then by endpoint identity.
func (c *Channel) SetTopic(ctx context.Context, topic string) error {
	if strings.HasPrefix(topic, topicMark) {
		return fmt.Errorf("set topic: text may not start with %q", topicMark)
	}
	if err := c.mayspeak(); err != nil {
		return err
	}
	at, err := c.broadcast(ctx, kindTopic, topic)
	if err != nil {
		return err
	}
	// A node never receives its own gossip back, so it applies what it
	// said here, by the rule every receiver applies it by: a topic
	// said later, or said at the same time by a higher id, stands.
	self := c.node.ID()
	c.mu.Lock()
	if c.newerTopic(self, at) {
		c.subject, c.by, c.at, c.set, c.firm = topic, self, at, true, true
	}
	c.mu.Unlock()
	return nil
}

// Topic returns the current channel topic, who set it, and when. It reports
// ok=false when no topic has been seen.
func (c *Channel) Topic() (text string, by Member, at time.Time, ok bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.set {
		return "", Member{}, time.Time{}, false
	}
	return c.subject, c.snapshot(c.by), c.at, true
}

// Members returns the channel's members.
//
// On a public channel that is everyone seen within the presence window,
// in the order first seen, with the local node first: presence is the
// only membership a public channel has.
//
// On a sealed channel it is the group's roster, in leaf order, which is
// a different question. A member that has stopped answering pings is
// still in the roster and can still read what is said, until the founder
// removes it; [Member.Seen] is what reports liveness there.
func (c *Channel) Members() []Member {
	if c.seal != nil {
		return c.seal.members()
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	cutoff := time.Now().Add(-presenceTimeout)
	self := c.node.ID()
	out := make([]Member, 0, len(c.order))
	for _, id := range c.order {
		m := c.members[id]
		if m == nil || (id != self && m.seen.Before(cutoff)) {
			continue
		}
		out = append(out, Member{ID: id, Nick: m.nick, Seen: m.seen})
	}
	return out
}

// Unverified reports how many envelopes arrived on this channel and did
// not decode or did not verify. The count has no sender attribution: an
// envelope that did not verify names nobody this node should believe.
//
// It is a total and not a rate, because the number worth acting on is
// not how fast they are arriving but whether any are at all. A count
// that climbs means something this node is meshed with, directly or
// through the overlay, is writing envelopes it cannot read - which on
// a public channel means the two are not running the same signing
// rule.
//
// A zero means less than it looks, and not for the reason it first
// seems to. It is not that this node declines to pass on what it
// cannot read: gossip forwards a swarm-scoped message when it arrives,
// before any of this runs and with no way for a verification result to
// reach it, so an envelope nobody on this side can read is relayed by
// this side all the same. What a zero says is narrower and harder -
// nothing unreadable has reached this node, by any path.
//
// That cuts the other way from how it first reads. Because forwarding
// does not wait on verification, an unreadable envelope spreads through
// a connected overlay like any other, so which neighbours gossip
// happened to give this node does not decide whether it counts. Two
// nodes on one overlay do not disagree for long. A zero next to a
// climbing count means the two are not on one overlay, or that this
// node has no neighbours at all and is not on any.
//
// Those two are the ones a count cannot tell apart, and they call for
// opposite responses: a node with no neighbours reports a zero about
// itself, while a node with neighbours and no path to the unreadable
// peer reports a zero about its own corner of the overlay. So the
// number is a statement about where this node sits, never about who is
// on the channel: it says "something I can reach writes what I cannot
// read", never "there is nobody out there I could not read".
//
// [Channel.Neighbors] is the other half of reading it and does less
// than it looks like too. An empty neighbour set makes a zero mean
// nothing at all. A non-empty one does not make it mean something: a
// node cut off with a neighbour still holds a neighbour, and reports
// a steady count of nothing while it hears nothing, which is exactly
// what a quiet channel looks like. Neither number alone distinguishes
// a channel with nothing to say from a node nobody can reach.
//
// A count that climbs says nothing about where to look, so the Refused
// event that reports the climb carries how far away the closest of
// them was: a neighbor, or some number of forwards out. That is the
// one thing about an envelope with no trustworthy attribution that is
// still worth knowing, and it is a property of the delivery rather
// than a claim about a party.
func (c *Channel) Unverified() uint64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.unverified
}

// A nearest is the fewest forwards any envelope of a run crossed to
// reach this node. Its zero value has seen nothing.
//
// It is kept for the run rather than per envelope because the report
// covers everything refused since the last one, and those need not
// have arrived by the same route. The nearest is the one summary that
// answers the question an unverified envelope raises: zero means a
// peer this node is meshed with signs differently, so the mesh is
// where to look; anything higher means nothing adjacent is wrong and
// the disagreement is out in the overlay. A maximum answers neither,
// and a mean answers neither twice.
type nearest struct {
	hops uint16
	any  bool
}

// saw records an envelope that arrived hops forwards away.
func (n *nearest) saw(hops uint16) {
	if !n.any || hops < n.hops {
		n.hops, n.any = hops, true
	}
}

// take returns the nearest seen and forgets it, for the next run.
func (n *nearest) take() uint16 {
	hops := n.hops
	*n = nearest{}
	return hops
}

// unverifiedText says how many envelopes did not verify and how far
// away the closest of them was, in the words the Refused event
// carries. A reader acts on the difference between one and many, so
// the singular says nothing about the interval it covers and the
// plural says everything.
//
// The distance is spelled as forwards and not as hops because zero is
// the reading that matters and "zero hops away" reads like a mistake.
func unverifiedText(n int, hops uint16) string {
	where := fmt.Sprintf("%d forwards away", hops)
	switch hops {
	case 0:
		where = "from a neighbor"
	case 1:
		where = "one forward away"
	}
	if n == 1 {
		return "an envelope did not verify, " + where
	}
	return fmt.Sprintf("%d envelopes did not verify in the last %v, the nearest of them %s", n, refusalReport, where)
}

// Neighbors returns the endpoints this node is directly meshed with on
// the channel's gossip topic, in no particular order.
//
// It is a different question from [Channel.Members] and answers what
// that cannot. Members is who has been heard from, which arrives
// epidemically and so includes endpoints many hops away and endpoints
// this node has no route to at all; neighbors is who this node is
// actually exchanging gossip with. When a channel's roster and its
// neighbors disagree about whether a peer is present, the roster is
// describing the swarm and the neighbors are describing this node's
// place in it.
//
// The set is who, and not how well. A node cut off from the rest of
// the channel keeps the neighbours it had and goes on exchanging
// gossip with them, so a partition that leaves this node in a pocket
// of two changes nothing here - measured: three nodes fell out of one
// channel within a second of each other and all three held the same
// neighbours, unchanged, for the sixteen minutes that followed. A
// non-empty set means this node is meshed with somebody. It is not
// evidence that somebody is meshed with the channel. [Split] is the
// event that reports the moment those two come apart, and carries
// this number for the same reason: it is what a reader needs and not
// what they want, which would be an answer.
//
// It is empty on a channel this node is alone in, and on a sealed
// channel it says nothing about the group's roster.
func (c *Channel) Neighbors() []key.EndpointID { return c.topic.Neighbors() }

// Events returns the channel's event stream. It ends when the channel is
// parted or its node is closed. Only one reader may range over it.
func (c *Channel) Events() iter.Seq2[Event, error] {
	return func(yield func(Event, error) bool) {
		for ev := range c.events {
			if !yield(ev, nil) {
				return
			}
		}
	}
}

// Part leaves the channel, telling the other members, who see reason as
// the [Parted] event's text; it may be empty. The channel's event stream
// ends and the Channel must not be used again.
func (c *Channel) Part(ctx context.Context, reason string) error {
	if err := checkText(reason); err != nil {
		return fmt.Errorf("part %s: %w", c.name, err)
	}
	c.node.forget(c)
	_, err := c.broadcast(ctx, kindPart, reason)
	c.shutdown()
	if err != nil {
		return fmt.Errorf("part %s: %w", c.name, err)
	}
	return nil
}

// shutdown stops the channel's goroutines and ends its event stream. It is
// safe to call more than once.
func (c *Channel) shutdown() {
	c.emu.Lock()
	if c.closed {
		c.emu.Unlock()
		return
	}
	c.closed = true
	close(c.quit)
	close(c.events)
	c.emu.Unlock()
	_ = c.topic.Close()
}

// broadcast signs and gossips one envelope, or seals and gossips one
// note when the channel is sealed. It returns the time the envelope or
// note carries, which is the time receivers order it by.
func (c *Channel) broadcast(ctx context.Context, k kind, text string) (time.Time, error) {
	if c.seal != nil {
		return c.seal.broadcast(ctx, k, text)
	}
	c.sending.Lock()
	defer c.sending.Unlock()
	e, err := sign(c.node.secret(), c.domain(), k, c.node.nextSeq(), c.node.Nick(), text)
	if err != nil {
		return time.Time{}, err
	}
	b, err := e.encode()
	if err != nil {
		return time.Time{}, err
	}
	if err := c.topic.Broadcast(ctx, b); err != nil {
		return time.Time{}, fmt.Errorf("broadcast to %s: %w", c.name, err)
	}
	// This node's own lines are part of the channel's history, and it
	// is the only member that will not receive them back from gossip.
	c.remember(kind(e.Kind), b)
	return e.at(), nil
}

// remember keeps one envelope for a joiner to ask about, when this node
// keeps history at all and the envelope is something that was said. The
// rest - presence, topics, nicks - is state a joiner learns from the
// channel itself within a presence interval, so serving it would be
// repeating in a weaker form what it is about to be told properly.
func (c *Channel) remember(k kind, b []byte) {
	if !c.node.history {
		return
	}
	if k != kindMessage && k != kindNotice {
		return
	}
	// Gossip owns the buffer an event arrived in; the reel outlives
	// the callback, so it keeps a copy of its own.
	c.recall.keep(bytes.Clone(b), time.Now())
}

// domain is what this channel's envelopes are signed against: the gossip
// topic they are said on. Binding it is what keeps a line said here from
// being presented as a line said somewhere else - which matters wherever
// an envelope arrives by some route other than the topic itself, as one
// served as history does. See [envelope.signed].
func (c *Channel) domain() [32]byte { return [32]byte(TopicID(c.name, c.secret)) }

// ping broadcasts presence, carrying the channel topic when this node knows
// one so that a new member learns it without asking.
func (c *Channel) ping(ctx context.Context) error {
	c.mu.Lock()
	text := ""
	if c.set && c.subject != "" {
		text = topicMark + c.subject
	}
	if m := c.members[c.node.ID()]; m != nil {
		m.seen = time.Now()
	}
	c.mu.Unlock()
	_, err := c.broadcast(ctx, kindPing, text)
	return err
}

// emit delivers ev to the channel's reader, or reports a lag when the
// reader has fallen behind.
//
// The last slot of the buffer is reserved for the lag report. Announcing a
// lag needs exactly the room the dropped event could not find, so a reader
// that is still stalled would leave nothing to announce it with; holding a
// slot back means the report always lands, at the point in the stream where
// the loss began. Further drops coalesce into that one report until the
// reader catches up and takes it, which is what a reader can act on: it
// learns its view is incomplete, not how incomplete.
func (c *Channel) emit(ev Event) {
	c.emu.Lock()
	defer c.emu.Unlock()
	if c.closed {
		return
	}
	if len(c.events) < cap(c.events)-1 {
		c.events <- ev
		return
	}
	select {
	case c.events <- Event{Kind: Lagged, Time: time.Now()}:
	default:
	}
}

// snapshot returns the public form of a member. The caller holds c.mu.
func (c *Channel) snapshot(id key.EndpointID) Member {
	m := c.members[id]
	if m == nil {
		return Member{ID: id, Rank: c.rank(id)}
	}
	return Member{ID: id, Nick: m.nick, Seen: m.seen, Rank: c.rank(id)}
}

// touch records a member as seen with the given nick and reports whether it
// is new to the channel. The caller holds c.mu.
//
// Three places call it, and only one of them is a message arriving:
// [Channel.apply], for a sender already authenticated, which is why a
// member in the roster is a member whose presence verified. The other
// two are this node writing itself down - [Node.Join] does it before
// anything is sent, and a sealed channel does it per committed member -
// so every roster holds this node from the moment it exists.
//
// That matters to anything reading the roster as evidence of reaching
// anybody. A node alone in a pocket, or one attached to peers whose
// envelopes it cannot verify, has a roster of exactly itself: the test
// is more than one member, never more than none.
func (c *Channel) touch(id key.EndpointID, nick string, at time.Time) bool {
	m := c.members[id]
	if m == nil {
		c.members[id] = &member{nick: nick, seen: at}
		c.order = append(c.order, id)
		return true
	}
	if nick != "" {
		m.nick = nick
	}
	if at.After(m.seen) {
		m.seen = at
	}
	return false
}

// drop removes a member. The caller holds c.mu.
func (c *Channel) drop(id key.EndpointID) {
	delete(c.members, id)
	c.order = slices.DeleteFunc(c.order, func(o key.EndpointID) bool { return o == id })
}

// run reads gossip events for the channel until it is parted.
func (c *Channel) run() {
	for ev, err := range c.topic.Events() {
		if err != nil {
			continue
		}
		c.handle(ev)
	}
}

// keepalive broadcasts presence and expires silent members.
func (c *Channel) keepalive() {
	ping := time.NewTicker(presenceInterval)
	defer ping.Stop()
	sweep := time.NewTicker(presenceSweep)
	defer sweep.Stop()
	rotate := time.NewTicker(rotateInterval)
	defer rotate.Stop()
	for {
		select {
		case <-c.quit:
			return
		case <-c.node.ctx.Done():
			return
		case <-ping.C:
			c.pingSoon()
		case <-sweep.C:
			c.expire()
		case <-rotate.C:
			c.rotateSoon()
		}
	}
}

// rotateSoon proposes new leaf keys, and on the founder commits what
// members have proposed since the last commit. Failures are ignored:
// the next tick tries again, and a rotation that does not happen leaves
// the channel working with the keys it had.
func (c *Channel) rotateSoon() {
	if c.seal == nil || !c.seal.seated() {
		return
	}
	ctx, cancel := context.WithTimeout(c.node.ctx, presenceSweep)
	defer cancel()
	_ = c.seal.rotate(ctx)
	if c.seal.isFounder() {
		_ = c.seal.flush(ctx)
	}
}

// pingSoon broadcasts presence with a bounded deadline, ignoring failures:
// the next tick tries again.
//
// It sends no faster than every receiver refills the allowance it
// charges presence to, because a node that announces itself faster than
// that is refused by everyone it is announcing itself to, and three
// refused announcements in a row is a presenceTimeout. Nothing sends on
// a schedule fast enough for that - the ticker is well inside it - but
// a neighbor coming up sends one too, and neighbors churn, which is a
// rate nothing bounds. A node whose mesh is unsettled is exactly the
// node whose presence others most need, and without this it is the one
// that talks itself out of their rosters.
func (c *Channel) pingSoon() {
	if !c.mayPing(time.Now()) {
		return
	}
	ctx, cancel := context.WithTimeout(c.node.ctx, presenceSweep)
	defer cancel()
	_ = c.ping(ctx)
}

// mayPing reports whether this node may announce itself at now, and
// records it if so. The rate is read off presenceRefill rather than
// picked: it is the one number that makes an honest node impossible to
// rate limit, since a receiver refuses presence only when it arrives
// faster than it refills.
func (c *Channel) mayPing(now time.Time) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if now.Sub(c.pinged) < presenceRefill() {
		return false
	}
	c.pinged = now
	return true
}

// splitText says how many members went in one sweep and what this node
// has left, in the words the [Split] event carries.
//
// A sweep that expires several members at once is not several members
// leaving. Presence arrives over the same mesh everything else does, so
// a node that stops hearing a shore of the channel renders that shore
// as departing, one line per nick, in the same second - which reads
// like news about them and is news about this node. Three of these were
// observed on one node in an afternoon, each time naming processes that
// were still running and still had neighbors of their own.
//
// The sentence stops at the neighbor count because the two readings it
// separates cannot be told apart from here. No neighbors left is this
// node falling out of the mesh entirely, which [Channel.seek] is
// already the answer to - and it is the answer to that case only, so
// nothing behind this notice repairs the other one. Neighbors still
// left is either those members really going or this node sitting in a
// pocket of the overlay with its own mesh intact, and locally those are
// the same observation: a non-empty neighbor set is not evidence of
// attachment. Nor is an unchanged one, which is the stronger thing and
// was measured: a probe whose single neighbor was the same endpoint for
// the whole of its life lost every inbound envelope from the channel
// in one second, and its neighbor table did not move then or in the
// forty minutes after. Two other nodes lost the same room in the same
// second and were reported gone by three bridges. A count sends the
// reader to look at both readings, and a verdict would send half of
// them to the wrong one.
func splitText(gone, neighbors int) string {
	left := fmt.Sprintf("%d neighbors", neighbors)
	switch neighbors {
	case 0:
		left = "no neighbors"
	case 1:
		left = "1 neighbor"
	}
	return fmt.Sprintf("%d members timed out together; this node has %s", gone, left)
}

// expire forgets what per-sender state has gone idle and deals with the
// members not heard from within the presence window. On a public channel
// they are dropped, and said to be once more when several go at once;
// see [splitText] for why that sweep is worth a sentence of its own. On
// a sealed channel the founder removes them.
func (c *Channel) expire() {
	now := time.Now()
	neighbors := c.topic.Neighbors()
	c.mu.Lock()
	gone, stale := c.timeouts(c.node.ID(), now)
	deaf := c.overdue(neighbors, now)
	c.mu.Unlock()
	for _, ev := range gone {
		c.emit(ev)
	}
	if len(gone) > 1 {
		c.emit(Event{Kind: Split, Text: splitText(len(gone), len(neighbors)), Time: time.Now()})
	}
	if len(deaf) > 0 {
		c.rejoin(deaf)
	}
	// On a sealed channel a member that stops answering is still a
	// recipient until the group says otherwise, so the founder turns
	// the timeout into a removal. The removal is not a ban: a member
	// that went quiet because the network did may come back, and it
	// comes back through the same invite exchange it joined with.
	//
	// So a timeout is a liveness decision and not a security boundary.
	// What is said between the removal and the return is unreadable to
	// the member that was out, and that is all it buys. Keeping an
	// endpoint out is [Channel.Kick].
	//
	// A member stays timed out until it is removed, so a removal that
	// fails is tried again at the next sweep.
	if c.seal == nil || !c.seal.isFounder() {
		return
	}
	for _, id := range stale {
		ctx, cancel := context.WithTimeout(c.node.ctx, presenceSweep)
		err := c.seal.evict(ctx, id, false)
		cancel()
		if err != nil {
			return
		}
	}
}

// timeouts prunes idle per-sender state and finds the members other than
// self not heard from within the presence window at now. The caller
// holds c.mu.
//
// On a public channel presence is the only membership there is, so a
// member that times out is dropped and reported in gone. On a sealed
// channel the roster decides membership: a member that times out is
// still on it, still reads what is said, and keeps its rank, which
// names the membership and not the liveness. It is left in place, with
// [Member.Seen] saying how long it has been away, and returned in stale
// for the founder to remove; the removal is what reports it gone.
func (c *Channel) timeouts(self key.EndpointID, now time.Time) (gone []Event, stale []key.EndpointID) {
	c.spent.prune(now)
	c.lastSeq.prune(now)
	cutoff := now.Add(-presenceTimeout)
	for _, id := range slices.Clone(c.order) {
		m := c.members[id]
		if m == nil || id == self || !m.seen.Before(cutoff) {
			continue
		}
		if c.seal != nil {
			stale = append(stale, id)
			continue
		}
		gone = append(gone, Event{
			Kind: Parted,
			From: Member{ID: id, Nick: m.nick, Seen: m.seen},
			Text: "timeout",
			Time: now,
		})
		c.drop(id)
	}
	return gone, stale
}

// overdue returns the neighbors that have gone presenceTimeout without
// being heard from, and starts or forgets the clock on the rest. A
// neighbor it returns has its clock restarted, so it is returned at most
// once a presenceTimeout. The caller holds c.mu.
//
// A neighbor that says nothing is not a quiet member, since every member
// pings well inside that window. It is what go-iroh gossip (v0.2.1)
// leaves behind when a member unsubscribes before this node's answer to
// its join reaches it: this node keeps the member in its active view and
// the answer marked as owed, so it answers none of the member's later
// joins, and the member, back on the topic, has nobody to send to. It
// hears the channel and the channel never hears it. See [Channel.rejoin].
func (c *Channel) overdue(neighbors []key.EndpointID, now time.Time) []key.EndpointID {
	cutoff := now.Add(-presenceTimeout)
	next := make(map[key.EndpointID]time.Time, len(neighbors))
	var out []key.EndpointID
	for _, id := range neighbors {
		if m := c.members[id]; m != nil && !m.seen.Before(cutoff) {
			continue
		}
		since, ok := c.unheard[id]
		switch {
		case !ok:
			since = now
		case !since.After(cutoff):
			out = append(out, id)
			since = now
		}
		next[id] = since
	}
	c.unheard = next
	return out
}

// rejoin sends a gossip join to each of the given neighbors. A join from
// this side is what the neighbor answers, and the exchange puts each back
// in the other's view, which is the one repair of the state [Channel.overdue]
// describes that is in this node's hands: the member cannot fix it by
// joining again, since it is this node's answer that is stuck. Failures
// are ignored; the neighbor is overdue again a presenceTimeout later.
func (c *Channel) rejoin(ids []key.EndpointID) {
	peers := make([]netaddr.EndpointAddr, len(ids))
	for i, id := range ids {
		peers[i] = c.node.PeerAddr(id)
	}
	ctx, cancel := context.WithTimeout(c.node.ctx, presenceSweep)
	defer cancel()
	_ = c.topic.JoinPeers(ctx, peers)
}

// handle applies one gossip event to the channel.
func (c *Channel) handle(ev gossip.Event) {
	switch ev.Kind {
	case gossip.NeighborUp:
		// Announce presence at once so the new neighbor does not wait a
		// full presence interval to see this node. pingSoon holds this
		// to a rate every receiver can afford; a neighbor that arrives
		// inside that window waits for the ticker instead, which is
		// still well inside presenceTimeout.
		go c.pingSoon()
		return
	case gossip.Lagged:
		c.emit(Event{Kind: Lagged, Time: time.Now()})
		return
	case gossip.Received:
	default:
		return
	}

	if c.seal != nil {
		out, behind := c.seal.receive(ev.Content)
		if behind {
			// Rate-limited: the epoch that said so is unauthenticated,
			// so anyone on the topic can ask this node to rejoin. The
			// refusal is reported because a steady stream of them is
			// the only sign of someone doing it on purpose.
			if c.seal.mayResync(time.Now()) {
				go c.resync()
			} else {
				c.emit(Event{Kind: Refused, Text: "rejoin rate-limited", Time: time.Now()})
			}
			return
		}
		for _, x := range out {
			c.emit(x)
		}
		return
	}

	e, err := decode(ev.Content, c.domain())
	if err != nil {
		// Reported on the same clock as a rate-limited sender, and
		// for the same reason. The failure this is here to make
		// visible - two builds that sign differently, so every
		// envelope from one fails at the other - is not an occasional
		// bad frame but every frame the far side sends, forever. One
		// event apiece would put a notice in front of every reader
		// per envelope, which is not a diagnosis, it is the flood
		// that makes people turn diagnostics off.
		now := time.Now()
		c.mu.Lock()
		c.unverified++
		// Round is the number of forwards between the peer that signed
		// this and the peer that handed it over, so zero means they are
		// the same peer. gossip leaves it zero for a direct delivery,
		// where they are the same peer too, and the two scopes agree
		// rather than collide at that reading.
		c.unverifiedNear.saw(ev.Round)
		n := c.unverifiedRun.refuse(now)
		hops := uint16(0)
		if n > 0 {
			hops = c.unverifiedNear.take()
		}
		c.mu.Unlock()
		if n > 0 {
			c.emit(Event{Kind: Refused, Text: unverifiedText(n, hops), Time: now})
		}
		return
	}
	from := e.sender()
	if from == c.node.ID() {
		return
	}
	// A directly delivered envelope must come from the peer that signed it.
	if ev.Scope == gossip.DeliveryNeighbors && from != ev.DeliveredFrom {
		return
	}
	now := time.Now()
	c.mu.Lock()
	// A public channel admits whoever speaks, so its roster is bounded
	// here or nowhere, and before anything is written down about the
	// sender: a window or a budget kept for an endpoint the roster
	// refused would be the unbounded table the cap is there to prevent.
	// Refuse the newcomer rather than evicting an established member:
	// evicting would let a sender churning keys push the channel's real
	// members out.
	if c.members[from] == nil && len(c.members) >= maxMembers {
		c.mu.Unlock()
		return
	}
	if !c.lastSeq.accept(from, e, now) {
		c.mu.Unlock()
		return
	}
	latest := c.lastSeq[from].top == e.Seq
	out := c.apply(kind(e.Kind), e.Nick, e.Text, from, e.at(), now, latest)
	c.mu.Unlock()
	for _, x := range out {
		// What is kept is what this node accepted and showed its own
		// reader, so a line refused here - rate-limited, from a
		// silenced member - is not one this node hands on as though
		// it had heard it.
		if x.Kind == Message || x.Kind == Notice {
			c.remember(kind(e.Kind), ev.Content)
		}
		c.emit(x)
	}
}

// apply updates channel state from one verified message and returns the
// events to emit. It is reached from a signed envelope on a public
// channel and from a sealed note on a sealed one; by the time it is
// called, from has been authenticated either way. The caller holds c.mu.
//
// latest reports that the message carries the highest sequence number
// accepted from its sender. Only such a message may rename the sender:
// one that gossip delivered late was sent under whatever nick the sender
// had then, and taking it would undo a rename until the next ping.
func (c *Channel) apply(k kind, nick, text string, from key.EndpointID, at, now time.Time, latest bool) []Event {
	// Leaving is always heard. A part costs this node nothing and
	// refusing one would keep a member in the roster against its will,
	// which is the opposite of what a limit is for.
	if k != kindPart {
		if c.node.quiet != nil && c.node.quiet(from) {
			return nil
		}
		if ok, refused := c.spent.spend(from, k, len(text), now, c.seal != nil); !ok {
			if refused == 0 {
				return nil
			}
			// Which allowance ran out is the whole of what a reader
			// can act on. Presence being refused drops a member that
			// is alive and talking out of this node's roster, and
			// says nothing about whether it can be heard; speech
			// being refused is the opposite. One word apart.
			what := "rate-limited"
			if k == kindJoin || k == kindPing {
				what = "presence rate-limited"
			}
			// A run that is still going says how much of it went
			// unheard. Without a count the second line and the
			// twentieth read the same, and a sender refused steadily
			// is exactly what the first line cannot distinguish from
			// a sender that stopped talking.
			text := what
			if refused > 1 {
				text = fmt.Sprintf("%s, %d refused in the last %v", what, refused, refusalReport)
			}
			return []Event{{Kind: Refused, From: c.snapshot(from), Text: text, Time: now}}
		}
	}
	if k == kindPart {
		m := c.members[from]
		if m == nil {
			return nil
		}
		ev := Event{Kind: Parted, From: Member{ID: from, Nick: m.nick, Seen: m.seen}, Text: text, Time: at}
		// The sender's window outlives it here, until [seqSet.prune]:
		// deleting it would let anyone holding the member's recent
		// envelopes play them back as new, and the clock alone refuses
		// them only once they are older than maxClockSkew.
		c.drop(from)
		return []Event{ev}
	}

	var out []Event
	was := ""
	if m := c.members[from]; m != nil {
		was = m.nick
	}
	if k == kindNick && text != "" {
		nick = text
	}
	if !latest {
		nick = ""
	}
	if c.touch(from, nick, now) {
		out = append(out, Event{Kind: Joined, From: c.snapshot(from), Text: nick, Time: at})
	} else if was == "" && nick != "" {
		// A sealed channel learns that a member exists from the
		// commit that added it, which carries an endpoint and no
		// nick; the nick arrives with the member's first message.
		// Report it as a change from nothing rather than leaving the
		// member nameless until it says something else.
		out = append(out, Event{Kind: NickChanged, From: c.snapshot(from), Text: nick, Time: at})
	}

	switch k {
	case kindJoin:
		// The join already produced a Joined event above if the member
		// was new; a repeat join needs nothing further.
	case kindPing:
		if subject, ok := strings.CutPrefix(text, topicMark); ok && !c.set && !c.silenced(from) {
			// A relayed topic carries text but not authorship, so any
			// later topic envelope supersedes it.
			c.subject, c.by, c.at, c.set, c.firm = subject, from, at, true, false
			out = append(out, Event{Kind: TopicChanged, From: c.snapshot(from), Text: subject, Time: at})
		}
	case kindMessage:
		// A moderated channel drops what an unvoiced member says and
		// keeps what its presence told us: being quiet is not being
		// absent.
		if !c.silenced(from) {
			out = append(out, Event{Kind: Message, From: c.snapshot(from), Text: text, Time: at})
		}
	case kindNotice:
		if !c.silenced(from) {
			out = append(out, Event{Kind: Notice, From: c.snapshot(from), Text: text, Time: at})
		}
	case kindMode:
		out = append(out, c.applyMode(text, from, at)...)
	case kindRank:
		out = append(out, c.applyRank(text, from, at)...)
	case kindTopic:
		// A topic is the loudest text in a channel, so moderation has
		// to cover it too; an unvoiced member that could still rewrite
		// the topic would be silenced in name only.
		if !c.silenced(from) && c.newerTopic(from, at) {
			c.subject, c.by, c.at, c.set, c.firm = text, from, at, true, true
			out = append(out, Event{Kind: TopicChanged, From: c.snapshot(from), Text: text, Time: at})
		}
	case kindNick:
		if latest && text != "" && text != was {
			out = append(out, Event{Kind: NickChanged, From: c.snapshot(from), Text: text, Old: was, Time: at})
		}
	}
	return out
}

// newerTopic reports whether a topic envelope from at time at supersedes
// the current topic. The caller holds c.mu.
func (c *Channel) newerTopic(from key.EndpointID, at time.Time) bool {
	if !c.set || !c.firm {
		return true
	}
	return newer(at, c.at, from, c.by)
}

// newer reports whether a statement made at time at by from supersedes
// the standing one, made at was by by. A zero was means there is none.
//
// Gossip is an epidemic overlay: two members can see the same pair of
// envelopes in opposite orders, so applying whichever arrived last would
// leave them permanently disagreeing about a topic or a rank. The rule
// is instead a property of the envelopes themselves - later wins, and a
// tie goes to the higher endpoint id - which is arbitrary but the same
// everywhere, so the order of arrival stops mattering. A tie with itself
// is not a conflict: an author restating its own position supersedes it.
func newer(at, was time.Time, from, by key.EndpointID) bool {
	if was.IsZero() || at.After(was) {
		return true
	}
	if at.Before(was) {
		return false
	}
	return from.Compare(by) >= 0
}

// Kick removes a member from a sealed channel and refuses it
// readmission. Only the founder can kick, because a kick is a removal
// from the group and only the founder commits; an operator moderates and
// voices instead, which are statements it can sign. ErrNotSealed is
// returned for a public channel and ErrNotFounder for a sealed one this
// node did not found.
//
// A kick is the only moderation here the removed member cannot ignore.
// [Channel.Moderate] and [Channel.Grant] are honored by a member running
// this code; a kick rotates the key schedule, so what is said next is
// unreadable whatever code it runs. It is also durable in a way a
// presence timeout is not.
//
// The kicked node learns it from the commit, asks the founder to be
// seated again, and is refused; its channel then ends, the last event
// on it being its own [Parted] with the text "removed".
//
// It does not reach an endpoint's other identities: the invite secret
// every member holds still admits any endpoint that presents it, so a
// kicked member who can mint a fresh endpoint id comes back as a
// stranger, and without rank. Keeping that out is what the allow policy
// passed to [Node.Found] is for.
func (c *Channel) Kick(ctx context.Context, id key.EndpointID) error {
	if c.seal == nil {
		return ErrNotSealed
	}
	if !c.seal.isFounder() {
		return ErrNotFounder
	}
	return c.seal.evict(ctx, id, true)
}

// Founder returns the channel's founder endpoint ID and true if the channel
// is sealed. On a public channel it returns (key.EndpointID{}, false).
func (c *Channel) Founder() (key.EndpointID, bool) {
	if c.seal == nil {
		return key.EndpointID{}, false
	}
	return c.seal.founder, true
}

// IsFounder reports whether the local node is the founder of the channel.
func (c *Channel) IsFounder() bool {
	if c.seal == nil {
		return false
	}
	return c.seal.isFounder()
}
