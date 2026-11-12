package irciroh

import (
	"bytes"
	"cmp"
	"context"
	"errors"
	"fmt"
	"slices"
	"sync"
	"time"

	"github.com/tmc/go-iroh-experiments/mlsiroh"
	"github.com/tmc/go-iroh/key"
	"github.com/tmc/go-iroh/postcard"
	"github.com/tmc/mls"
)

// A sealed channel is an MLS group (RFC 9420) carried on the same gossip
// topic a public channel uses. The topic still decides who receives a
// message; the group decides who can read one.
//
// Every member is an iroh endpoint, because every leaf carries the
// mlsiroh binding: a credential naming the member's endpoint id, signed
// by that endpoint key over the leaf's own signature key. So the roster
// is a list of endpoints a member can dial, and the founder's admission
// policy is written in endpoint ids rather than in tokens.
//
// # The founder sequences
//
// MLS requires a total order on commits per epoch. Two members that
// commit from the same epoch derive different secrets and can no longer
// read each other, unrecoverably. A serverless channel has nobody to
// impose that order, so a sealed channel does not ask one to exist: the
// founder is the only member that commits. Everyone else joins through
// the founder, and a member that wants out says so and waits to be
// removed. The cost is that a channel whose founder is gone cannot
// change its membership; it keeps working for the members it has. One
// committer is the supported mode by decision rather than a stopgap:
// ordering commits among several members is a separate design, and
// handing the founder's role to another member is the next step if a
// founder's absence starts to matter.
//
// # Falling behind
//
// Gossip does not promise delivery, so a member can miss a commit and be
// stranded an epoch back, unable to decrypt anything. It finds out
// without being told: [mls.ParseHeader] reads the group id and epoch out
// of a message that it cannot open, so a member that sees an epoch ahead
// of its own knows it missed a commit. Recovery is to join again, which
// is also what a member does after losing its state entirely. The
// founder handles both the same way, by removing the endpoint's existing
// leaves in the commit that adds the new one - see [mlsiroh.Leaves].
//
// A message from the very next epoch is not yet evidence of that: gossip
// does not order a commit ahead of what is said after it, and the resend
// every member makes on an epoch change is exactly the traffic that
// races the commit. So a member holds a few such messages and opens them
// once the commit lands, and rejoins only if it is still behind after
// [aheadGrace] or sees an epoch two or more ahead - see [sealed.hold].
//
// That header is not signed, so "I am behind" is a claim anyone on the
// topic can make, and acting on it costs the founder a commit. A node
// therefore rejoins at most once per presence interval and reports the
// refusals as [Refused] events. This bounds the cost; it does not remove
// it, and there is no way to remove it while the epoch a member needs in
// order to know it is behind is one it cannot authenticate.
//
// # Rotation
//
// A member proposes new keys for its own leaf every so often and the
// founder commits what has been proposed - see [sealed.rotate] and
// [sealed.flush]. Without that, a leaf changes only when someone joins
// or leaves, so a channel with a settled roster never recovers from a
// member being compromised: whoever copied that member's state reads
// what it reads, for as long as it is in the channel. Rotation bounds
// exposure when an update is delivered and committed. It is not a
// fixed recovery deadline: the founder may be offline, delivery may
// fail, and the endpoint key must remain uncompromised. The founder
// retains its signing key; its own Update is not accepted in its commit.
//
// The proposal is the one thing a member other than the founder may
// send on the handshake path, and it is the only one that is not a
// membership decision: it changes that member's keys and nothing else.
// The founder still decides when a commit happens, so the total order
// on commits is unchanged.
//
// # Crossing an epoch
//
// A message sealed in one epoch cannot be read in the next, so a
// message in flight when a commit lands would be lost to every member
// that applied the commit first. Instead a sender keeps what it said
// recently and seals it again after each epoch change, and receivers
// drop the copies they already have by sequence number - see
// [sealed.resend]. Old epoch keys are discarded. Recent plaintext remains in the sender's outbox
// for resendWindow, so compromise during that window can expose it.
// A line can arrive after lines said later; it
// carries the time it was said.
//
// Within an epoch, order does not matter: mls keeps the keys of the
// generations a receiver skipped until they are used or the epoch ends,
// up to 1024 behind the newest, so a note overtaken by later ones from
// the same sender is still opened when it arrives.
//
// Two things are still lost. A note is not resent across a commit that
// added an endpoint, because the new member would read what was said
// before it arrived. And a note outlives the resend window only by not
// being resent, so a member stranded behind for longer than that loses
// what it said while it was.
//
// # What the seal does not cover
//
// Everything on the topic is an MLS PrivateMessage, commits and
// proposals included, so the endpoints a commit adds or removes and
// the leaf a rotation replaces are read only by members. A holder of a
// leaked ticket who never joins reads none of it. What it does see:
//
//   - each message's cleartext header: the group id, which is the
//     channel name, the epoch, and the content type, so it can tell a
//     commit from a proposal from a line and count epochs;
//   - sizes, since nothing is padded, and a commit that adds a member
//     carries a key package and is larger than one that does not;
//   - timing: when members speak, rotate and ping, and when the
//     founder commits;
//   - the swarm itself: it is a gossip peer on the topic, and learns
//     the endpoint ids of the peers it connects to and that forward to
//     it, which in a small channel is most of the roster.
//
// The Welcome and the key package it answers never touch the topic:
// they cross the founder's invite connection, and the Welcome is
// encrypted to the joiner - see [InviteALPN]. So the topic being
// derived from the invite secret, [SealedTopicID], is still what keeps
// the last two items above from anyone without a ticket.
//
// Removal is not revocation by itself. A commit removes a leaf,
// and a leaf is not an identity: the removed endpoint still holds the
// invite secret, which names nobody, and can rejoin with it. That is
// what makes a netsplit recoverable, and it is why keeping an endpoint
// out is a separate decision - [Channel.Kick] - rather than a
// consequence of a presence timeout.
//
// Presence is unchanged and stays outside the seal only in the sense
// that it is carried as an ordinary sealed message: a member of the
// group that is not currently answering pings is still in the roster.
// "In the channel" and "online" are different questions here, and
// [Channel.Members] answers the first while [Member.Seen] answers the
// second.
type sealed struct {
	ch      *Channel
	sk      key.SecretKey
	founder key.EndpointID
	invite  []byte

	mu sync.Mutex
	// allow admits a joiner. It is consulted by the founder only, and
	// a nil allow admits anyone holding the invite secret.
	allow  func(key.EndpointID) bool
	client *mls.Client
	group  *mls.Group
	roster map[key.EndpointID]mls.LeafIndex
	// banned is the founder's record of endpoints removed on purpose,
	// as opposed to removed for going quiet. A commit removes a leaf,
	// and a leaf is not an identity: without this the removed endpoint
	// rejoins through the invite exchange with the secret it already
	// holds, and the removal means nothing. Only the founder keeps it,
	// because only the founder admits. state is where it survives a
	// restart, and is nil when the node has no state directory.
	banned map[key.EndpointID]bool
	state  *state
	// lastResync and resyncEvery bound how often an unauthenticated
	// message can make this node rejoin. mls.ParseHeader reads an epoch
	// out of bytes nobody signed, so "I am behind" is an
	// attacker-suppliable claim and must not be able to schedule
	// unbounded work. A zero resyncEvery means presenceInterval.
	lastResync  time.Time
	resyncEvery time.Duration
	// pending is the set of leaves with an update staged for the
	// founder's next commit. mls remembers the proposals themselves and
	// keeps only the latest update for a leaf, so this is one entry per
	// leaf rather than a count of proposals - see [sealed.flush].
	pending map[mls.LeafIndex]bool
	// ahead holds messages from the epoch after this node's, which it
	// cannot open until the commit that starts that epoch arrives, and
	// aheadSince is when the first of them did - see [sealed.hold].
	ahead      [][]byte
	aheadSince time.Time
	// removed is set when a commit from the founder removed this
	// node. Unlike an epoch read from a header it is authenticated,
	// so it is what lets a refused rejoin end the channel rather than
	// leave it running in an epoch nobody else is in. See
	// [Channel.resync].
	removed bool
	// outbox holds the notes this node sealed recently, oldest
	// first, so that an epoch change can seal them again - see
	// [sealed.resend]. seen is the other half: the sequence numbers
	// accepted from each member, so that a note sealed twice is
	// shown once.
	outbox []outgoing
	seen   map[key.EndpointID]recent
	// sending is held from sealing a message or making a commit until
	// it has been handed to gossip, and is taken before mu. So what
	// this node says leaves in the order it was sealed, and a commit
	// leaves before anything sealed in the epoch it starts.
	sending sync.Mutex
}

// resendWindow is how long a note stays in the outbox. A note is lost
// to an epoch change only if it was sealed before its sender applied
// the commit, and a sender that missed the commit learns of it from the
// next message in the new epoch - at worst a presence interval later,
// plus aheadGrace if that message is from the very next epoch - and
// then rejoins, which takes at most inviteTimeout. The window is the
// sum. It is not a multiple of the presence interval alone: the time a
// commit takes to reach a member that did not miss it has nothing to do
// with how often members ping.
func resendWindow() time.Duration { return presenceInterval + aheadGrace() + inviteTimeout }

// aheadGrace is how long a message from the next epoch may wait for its
// commit before this node decides it missed the commit. The commit and
// the messages after it leave the founder and the other members within
// moments of each other, so they are apart by the difference between
// two gossip paths, which is round trips rather than seconds. A sweep
// interval is well past that, and it is also all a member that did miss
// the commit waits before it rejoins.
func aheadGrace() time.Duration { return presenceSweep }

// maxAhead bounds the messages held for the next epoch. The traffic most
// likely to race a commit is the resend it provokes, and one sender
// resends at most maxOutbox notes.
const maxAhead = maxOutbox

// maxOutbox bounds the outbox. It is the burst a settled sender may
// deliver at once, because a resend of more than that is refused by the
// members it is meant for.
const maxOutbox = sendBurst

// maxSeen is how many sequence numbers are remembered per member. It is
// larger than the outbox, whose notes are all a resend can repeat, by
// enough to cover the presence the member sent in the same time.
const maxSeen = 4 * maxOutbox

// outgoing is one note in the outbox, with the roster it was first
// sealed to. A roster map is replaced whole and never changed, so
// holding it is holding a snapshot.
type outgoing struct {
	at     time.Time
	plain  []byte
	roster map[key.EndpointID]mls.LeafIndex
}

// noteVersion is the format version of a sealed channel's plaintext.
const noteVersion = 2

// A note is the plaintext of one message on a sealed channel. MLS
// authenticates the sender and rejects a replay within an epoch, so a
// note carries neither an [envelope]'s sender nor its signature.
//
// It does carry a sequence number, because a note may be sealed more
// than once: after an epoch change its sender seals it again under the
// new epoch - see [sealed.resend] - and MLS sees each sealing as a new
// message. Seq is what makes the second one recognizably the first.
type note struct {
	Version uint8
	Kind    uint8
	Seq     uint64
	Time    int64
	Nick    string
	Text    string
}

// decodeNote parses the plaintext of a sealed message and refuses a note
// whose nick or text [checkLine] would not send.
func decodeNote(b []byte) (note, error) {
	var n note
	if err := postcard.Unmarshal(b, &n); err != nil {
		return note{}, fmt.Errorf("decode note: %w", err)
	}
	if n.Version != noteVersion {
		return note{}, fmt.Errorf("decode note: version %d: %w", n.Version, errVersion)
	}
	if err := checkLine(n.Nick, n.Text); err != nil {
		return note{}, fmt.Errorf("decode note: %w", err)
	}
	return n, nil
}

// A recent is the set of sequence numbers most recently accepted from
// one member, in ascending order and at most maxSeen of them.
type recent []uint64

// add records seq and reports whether it had not been seen. A number
// older than everything remembered is refused: it is either a note
// sealed again long after it was first delivered, or one reordered
// behind maxSeen later ones, and in both cases it is stale.
func (r *recent) add(seq uint64) bool {
	i, found := slices.BinarySearch(*r, seq)
	if found {
		return false
	}
	if len(*r) >= maxSeen {
		if i == 0 {
			return false
		}
		*r = slices.Delete(*r, 0, 1)
		i--
	}
	*r = slices.Insert(*r, i, seq)
	return true
}

// isFounder reports whether this node founded the channel, and so is the
// member that commits.
func (s *sealed) isFounder() bool { return s.founder == s.ch.node.ID() }

// seated reports whether the channel holds group state yet. Between
// subscribing to the topic and being welcomed by the founder it does
// not.
func (s *sealed) seated() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.group != nil
}

// broadcast seals one note and gossips it.
func (s *sealed) broadcast(ctx context.Context, k kind, text string) (time.Time, error) {
	s.sending.Lock()
	defer s.sending.Unlock()
	now := time.UnixMilli(time.Now().UnixMilli())
	b, err := s.seal(k, text, now)
	if err != nil {
		return time.Time{}, err
	}
	if err := s.ch.topic.Broadcast(ctx, b); err != nil {
		return time.Time{}, fmt.Errorf("broadcast to %s: %w", s.ch.name, err)
	}
	return now, nil
}

// seal encodes and seals one note, and keeps it in the outbox unless it
// is presence. A ping is not worth sending twice: the next one
// supersedes it.
func (s *sealed) seal(k kind, text string, now time.Time) ([]byte, error) {
	nick := s.ch.node.Nick()
	if err := checkLine(nick, text); err != nil {
		return nil, fmt.Errorf("seal note: %w", err)
	}
	n := note{Version: noteVersion, Kind: uint8(k), Seq: s.ch.node.nextSeq(), Time: now.UnixMilli(), Nick: nick, Text: text}
	plain, err := postcard.Marshal(n)
	if err != nil {
		return nil, fmt.Errorf("encode note: %w", err)
	}
	if len(plain) > MaxEnvelopeSize {
		return nil, fmt.Errorf("encode note: %d bytes: %w", len(plain), ErrTooLarge)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.group == nil {
		return nil, fmt.Errorf("%s: not yet welcomed", s.ch.name)
	}
	b, err := s.protect(plain)
	if err != nil {
		return nil, err
	}
	if k != kindPing {
		if len(s.outbox) >= maxOutbox {
			s.outbox = slices.Delete(s.outbox, 0, 1)
		}
		s.outbox = append(s.outbox, outgoing{at: now, plain: plain, roster: s.roster})
	}
	return b, nil
}

// protect seals plaintext in the current epoch. The caller holds s.mu.
func (s *sealed) protect(plain []byte) ([]byte, error) {
	msg, err := s.group.Protect(nil, plain)
	if err != nil {
		return nil, fmt.Errorf("seal for %s: %w", s.ch.name, err)
	}
	b, err := mls.Marshal(msg)
	if err != nil {
		return nil, fmt.Errorf("encode sealed message: %w", err)
	}
	return b, nil
}

// resend seals the outbox again in the current epoch and gossips it.
// The caller holds s.mu, and calls it whenever the epoch has just
// changed: after applying a commit, after making one, and after a
// rejoin. The work happens once the caller lets go of s.mu.
//
// A note sealed in one epoch cannot be opened in the next, and a member
// discards a message from an epoch it has left. So a note that was in
// flight when a commit landed - sealed by a sender that had not yet
// applied it, or by the founder just before making it - reaches nobody
// who got there first. The sender cannot tell who that was: gossip has
// no acknowledgements, and this node does not receive its own messages
// back. So every note in the outbox goes again, and the receivers drop
// what they already have by its sequence number - see [recent].
//
// A note goes again only to an epoch whose members were all members
// when it was first sealed. Resending across a commit that added an
// endpoint would show that endpoint what was said before it arrived,
// which the seal promises it cannot read; so a note in flight across an
// addition is still lost, to everyone that applied the commit first.
// Rotations and removals add nobody, and neither does a member's
// rejoin, which re-adds an endpoint that was already there.
//
// Only the plaintext is kept, never an old epoch's keys. A resend is
// a new message under the new epoch's keys; compromise of the sender
// during [resendWindow] can still expose its retained plaintext.
func (s *sealed) resend() {
	if len(s.outbox) == 0 {
		return
	}
	// Not under s.mu, and not on the receive loop that applies
	// commits: a broadcast waits on the network. The notes are sealed
	// and sent under s.sending, so that nothing this node says is
	// sealed after them and gossiped before them - see sending.
	go func() {
		s.sending.Lock()
		defer s.sending.Unlock()
		s.mu.Lock()
		b := s.reseal(time.Now())
		s.mu.Unlock()
		ctx, cancel := context.WithTimeout(s.ch.node.ctx, presenceSweep)
		defer cancel()
		for _, m := range b {
			if err := s.ch.topic.Broadcast(ctx, m); err != nil {
				return
			}
		}
	}()
}

// within reports whether every member of roster is also in was.
func within(roster, was map[key.EndpointID]mls.LeafIndex) bool {
	for id := range roster {
		if _, ok := was[id]; !ok {
			return false
		}
	}
	return true
}

// reseal drops what has aged out of the outbox and seals the rest in the
// current epoch. The caller holds s.mu. A node the commit removed has
// nobody left to resend to, and forgets the outbox.
func (s *sealed) reseal(now time.Time) [][]byte {
	s.outbox = slices.DeleteFunc(s.outbox, func(o outgoing) bool {
		return now.Sub(o.at) > resendWindow()
	})
	if _, ok := s.roster[s.ch.node.ID()]; !ok {
		s.outbox = nil
		return nil
	}
	var out [][]byte
	for _, o := range s.outbox {
		if !within(s.roster, o.roster) {
			continue
		}
		b, err := s.protect(o.plain)
		if err != nil {
			continue
		}
		out = append(out, b)
	}
	return out
}

// receive applies one gossip payload. It returns the events to emit and
// whether the node has fallen behind and must rejoin.
func (s *sealed) receive(content []byte) (out []Event, behind bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.open(content, time.Now())
}

// open is receive with s.mu held.
func (s *sealed) open(content []byte, now time.Time) (out []Event, behind bool) {
	h, err := mls.ParseHeader(content)
	if err != nil {
		return nil, false
	}
	if s.group == nil {
		return nil, false
	}
	if string(h.GroupID) != string(s.group.Context.GroupID) {
		return nil, false
	}
	// A commit names the epoch it ends, and any other message the epoch
	// it was sent in, so in both cases an epoch past our own is a commit
	// we have not seen - yet, if it is only the next one.
	switch epoch := s.group.Epoch(); {
	case h.Epoch == epoch+1:
		return nil, s.hold(content, now)
	case h.Epoch > epoch:
		return nil, true
	case h.Epoch < epoch:
		return nil, false
	}

	var msg mls.Message
	if err := mls.Unmarshal(content, &msg); err != nil {
		return nil, false
	}
	// Proposals and commits are encrypted like everything else, so the
	// message is routed by the content mls authenticated, not by how it
	// was framed. It is opened with Unprotect rather than Handle because
	// Handle stages any proposal and applies any commit, and this channel
	// accepts a proposal only if it is an update and a commit only if the
	// founder made it: the checks go between opening and applying.
	c, err := s.group.Unprotect(&msg)
	if err != nil {
		return nil, false
	}
	switch c.Content.ContentType {
	case mls.ContentTypeApplication:
		return s.application(c, now), false
	case mls.ContentTypeProposal:
		s.stage(c)
		return nil, false
	case mls.ContentTypeCommit:
		return s.commit(c, now)
	}
	return nil, false
}

// hold keeps a message from the next epoch until the commit that starts
// it arrives, and reports whether this node should instead take itself
// to have missed that commit: it has been waiting for it for aheadGrace.
// A message past maxAhead is dropped rather than held, and a resend or
// the next ping repeats what it said. The caller holds s.mu.
//
// Nothing here trusts the epoch any more than before: an attacker that
// sends a message claiming the next epoch fills at most maxAhead slots
// and can still ask for a rejoin only at the rate mayResync allows.
func (s *sealed) hold(content []byte, now time.Time) bool {
	if s.aheadSince.IsZero() {
		s.aheadSince = now
	}
	if now.Sub(s.aheadSince) >= aheadGrace() {
		return true
	}
	if len(s.ahead) < maxAhead {
		s.ahead = append(s.ahead, slices.Clone(content))
	}
	return false
}

// advanced is called after the epoch changes, with s.mu held. It forgets
// the proposals staged for the epoch just ended, opens the messages
// that were held for the one just begun, and seals the outbox again.
func (s *sealed) advanced(now time.Time) []Event {
	s.pending = nil
	held := s.ahead
	s.ahead, s.aheadSince = nil, time.Time{}
	out := s.reroster()
	// A held commit ends the epoch the other held messages were sent
	// in, so it is opened after them: opened first, it would leave them
	// behind. A PrivateMessage carries its content type in the clear,
	// which is what tells a commit apart before it is opened.
	slices.SortStableFunc(held, func(a, b []byte) int {
		return cmp.Compare(heldOrder(a), heldOrder(b))
	})
	for _, b := range held {
		// A held message is from what is now the current epoch,
		// unless a rejoin went past it, and then it is old.
		evs, _ := s.open(b, now)
		out = append(out, evs...)
	}
	s.resend()
	return out
}

// heldOrder is 1 for a commit and 0 for anything else.
func heldOrder(b []byte) int {
	var m mls.Message
	if mls.Unmarshal(b, &m) == nil && m.PrivateMessage != nil && m.PrivateMessage.ContentType == mls.ContentTypeCommit {
		return 1
	}
	return 0
}

// commit applies an opened commit and reports whether it removed this
// node. The caller holds s.mu.
func (s *sealed) commit(content *mls.AuthenticatedContent, now time.Time) (out []Event, removed bool) {
	// Only the founder commits. A commit from anyone else is either a
	// mistake or an attempt to fork the group, and applying it would
	// strand this node from the members that did not. The sender is
	// the leaf mls decrypted from the sender data and checked the
	// signature against, so it is known before anything is applied.
	if !s.sentByFounder(content.Content.Sender) {
		return nil, false
	}
	next, err := s.group.ApplyCommit(content)
	if errors.Is(err, mls.ErrRemoved) {
		if s.reseats(content.Content.Commit) {
			// This node's own rejoin, which removes its old leaf
			// and adds its new one at once. The Welcome that goes
			// with it is on its way.
			return nil, false
		}
		s.removed = true
		// Every other member drops this node's entry, and the rank
		// with it, when it applies this commit (see reroster). Forget
		// the rank here too, so that if the founder lets this node
		// back in it starts where everyone else has it rather than
		// wielding an authority nobody honors.
		s.ch.mu.Lock()
		if m := s.ch.members[s.ch.node.ID()]; m != nil {
			m.rank, m.rankAt, m.rankBy = Ordinary, time.Time{}, key.EndpointID{}
		}
		s.ch.mu.Unlock()
		return nil, true
	}
	if err != nil {
		return nil, false
	}
	s.group = next
	return s.advanced(now), false
}

// stage remembers a member's update proposal. The caller holds s.mu.
//
// Every member stages, not only the founder. The founder's commit
// carries a staged proposal by reference rather than by value, so a
// member that had not kept the proposal cannot apply the commit, and
// falls behind and rejoins on every rotation. A proposal the founder
// never commits costs a member nothing: it is forgotten with the epoch.
//
// Only updates are accepted. An add or a remove from a member is a
// membership decision, and on this channel membership is the founder's
// alone - see [Channel.Invite] and [Channel.Kick]. A rotation is not a
// membership decision: it changes a member's keys and nothing else,
// which is why it is the one proposal a member may send.
func (s *sealed) stage(content *mls.AuthenticatedContent) {
	if content.Content.Proposal.Type != mls.ProposalTypeUpdate {
		return
	}
	if content.Content.Sender.Type != mls.SenderTypeMember {
		return
	}
	if err := s.group.AddProposal(content); err != nil {
		return
	}
	if s.pending == nil {
		s.pending = make(map[mls.LeafIndex]bool)
	}
	s.pending[mls.LeafIndex(content.Content.Sender.LeafIndex)] = true
}

// sentByFounder reports whether a sender is the channel's founder. The
// caller holds s.mu.
func (s *sealed) sentByFounder(from mls.Sender) bool {
	if from.Type != mls.SenderTypeMember {
		return false
	}
	leaf := s.group.Tree.Leaf(mls.LeafIndex(from.LeafIndex))
	if leaf == nil {
		return false
	}
	id, err := mlsiroh.VerifyLeaf(leaf)
	if err != nil {
		return false
	}
	return id == s.founder
}

// application reads one opened note. The caller holds s.mu.
func (s *sealed) application(content *mls.AuthenticatedContent, now time.Time) []Event {
	if content.Content.Sender.Type != mls.SenderTypeMember {
		return nil
	}
	leaf := s.group.Tree.Leaf(mls.LeafIndex(content.Content.Sender.LeafIndex))
	if leaf == nil {
		return nil
	}
	// The sender is whoever the leaf's binding names, which the
	// transport never had to tell us: MLS authenticated the leaf and
	// mlsiroh resolves it to an endpoint.
	from, err := mlsiroh.VerifyLeaf(leaf)
	if err != nil {
		return nil
	}
	if from == s.ch.node.ID() {
		return nil
	}
	n, err := decodeNote(content.Content.ApplicationData)
	if err != nil {
		return nil
	}
	// A note sealed again after an epoch change is the same note, and
	// is shown once. The first copy to arrive is the one shown, even if
	// it arrives after lines said later: it carries the time it was
	// said, and dropping it would lose it, which is what resending is
	// there to prevent.
	if s.seen == nil {
		s.seen = make(map[key.EndpointID]recent)
	}
	r := s.seen[from]
	fresh := r.add(n.Seq)
	s.seen[from] = r
	if !fresh {
		return nil
	}
	latest := r[len(r)-1] == n.Seq
	// The time is the sender's to choose, and a mode, a rank and a
	// topic go to the latest statement - see [newer]. A time far ahead
	// would freeze them for as long as it stays ahead, so it counts as
	// said now. The line itself is authenticated and still shown.
	at := time.UnixMilli(n.Time)
	if at.After(now.Add(maxClockSkew)) {
		at = now
	}
	s.ch.mu.Lock()
	out := s.ch.apply(kind(n.Kind), n.Nick, n.Text, from, at, now, latest)
	s.ch.mu.Unlock()
	if kind(n.Kind) == kindPart && s.isFounder() {
		// Leaving is a request: the member cannot take itself out of
		// the group, because only the founder commits. Until the
		// removal lands it can still read what is said.
		s.pendingEvict(from)
	}
	return out
}

// pendingEvict removes a member in the background. The caller holds
// s.mu, which evict also takes.
func (s *sealed) pendingEvict(id key.EndpointID) {
	go func() {
		ctx, cancel := context.WithTimeout(s.ch.node.ctx, inviteTimeout)
		defer cancel()
		_ = s.evict(ctx, id, false)
	}()
}

// reroster recomputes the membership from the ratchet tree and returns
// the events the change produced. The caller holds s.mu.
func (s *sealed) reroster() []Event {
	now := time.Now()
	next := make(map[key.EndpointID]mls.LeafIndex)
	for i := mls.LeafIndex(0); i < s.group.Tree.Size(); i++ {
		leaf := s.group.Tree.Leaf(i)
		if leaf == nil {
			continue
		}
		id, err := mlsiroh.VerifyLeaf(leaf)
		if err != nil {
			continue
		}
		next[id] = i
	}
	var out []Event
	s.ch.mu.Lock()
	for id := range next {
		if _, ok := s.roster[id]; ok {
			continue
		}
		s.ch.touch(id, "", now)
		out = append(out, Event{Kind: Joined, From: s.ch.snapshot(id), Time: now})
	}
	for id := range s.roster {
		if _, ok := next[id]; ok {
			continue
		}
		if _, known := s.ch.members[id]; !known {
			// Already gone from the channel's own view, which is
			// where a presence timeout and a part take a member
			// out before the commit that removes its leaf catches
			// up. Reporting it again would be a second parting for
			// one departure, and a worse one: the nick went with
			// the member.
			continue
		}
		ev := Event{Kind: Parted, From: s.ch.snapshot(id), Text: "removed", Time: now}
		s.ch.drop(id)
		out = append(out, ev)
	}
	s.ch.mu.Unlock()
	s.roster = next
	for id := range s.seen {
		if _, ok := next[id]; !ok {
			delete(s.seen, id)
		}
	}
	return out
}

// members returns the roster: every endpoint holding a leaf, in leaf
// order, with the liveness this node has observed for it.
func (s *sealed) members() []Member {
	s.mu.Lock()
	ids := make([]key.EndpointID, 0, len(s.roster))
	for id := range s.roster {
		ids = append(ids, id)
	}
	roster := s.roster
	s.mu.Unlock()
	slices.SortFunc(ids, func(a, b key.EndpointID) int { return int(roster[a]) - int(roster[b]) })

	s.ch.mu.Lock()
	defer s.ch.mu.Unlock()
	out := make([]Member, 0, len(ids))
	for _, id := range ids {
		out = append(out, s.ch.snapshot(id))
	}
	return out
}

// admit commits the addition of a joiner, removing any leaf the joiner
// already holds, and returns the welcome and the tree to send back. Only
// the founder calls it.
func (s *sealed) admit(ctx context.Context, kp *mls.KeyPackage, joiner key.EndpointID) (*mls.Welcome, mls.RatchetTree, []Event, error) {
	s.sending.Lock()
	defer s.sending.Unlock()

	// An endpoint that lost its state, or fell behind and is coming
	// back, already holds a leaf. MLS would be content to give it a
	// second one, because in MLS the leaf key is the identity; this
	// channel would then have one member listed twice and a stale leaf
	// that still counts as a recipient.
	s.mu.Lock()
	var proposals []*mls.Proposal
	for _, i := range mlsiroh.Leaves(s.group.Tree, joiner) {
		proposals = append(proposals, &mls.Proposal{
			Type:   mls.ProposalTypeRemove,
			Remove: &mls.Remove{Removed: uint32(i)},
		})
	}
	proposals = append(proposals, &mls.Proposal{
		Type: mls.ProposalTypeAdd,
		Add:  &mls.Add{KeyPackage: *kp},
	})
	next, commit, welcome, err := s.group.Commit(proposals)
	s.mu.Unlock()
	if err != nil {
		return nil, nil, nil, fmt.Errorf("committing %v into %s: %w", joiner.Short(), s.ch.name, err)
	}
	if welcome == nil {
		return nil, nil, nil, fmt.Errorf("commit for %v produced no welcome", joiner.Short())
	}
	tree := next.Tree.Clone()
	// RFC 9420, Section 14: the welcome must not be delivered before
	// the commit is accepted. The founder is the only committer, so
	// its own acceptance is the whole of that; publishing the commit
	// first also keeps a member that hears it before the joiner does
	// from seeing an epoch it cannot explain.
	out, err := s.publish(ctx, commit, next)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("publishing the commit for %s: %w", s.ch.name, err)
	}
	return welcome.Welcome, tree, out, nil
}

// publish gossips a commit the founder made and then moves the group to
// the epoch it starts. The caller holds s.sending and not s.mu.
//
// The broadcast waits on the network, so it is not made under s.mu,
// which the receive loop needs for every message. The group cannot
// change under it meanwhile: only the founder commits, it commits only
// under s.sending, and it applies no one else's commit. What does
// change is that a proposal staged while the commit is in flight goes
// with the epoch it was made in, as it would have had it arrived a
// moment later. s.sending is what keeps anything this node seals in the
// new epoch, a resend included, from leaving before the commit does.
//
// A commit that fails to go out is not applied, so the founder stays in
// the epoch every other member is in.
func (s *sealed) publish(ctx context.Context, commit *mls.Message, next *mls.Group) ([]Event, error) {
	b, err := mls.Marshal(commit)
	if err != nil {
		return nil, err
	}
	if err := s.ch.topic.Broadcast(ctx, b); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.group = next
	return s.advanced(time.Now()), nil
}

// evict commits the removal of a member. Only the founder calls it, and
// it is a no-op for an endpoint that holds no leaf.
//
// A ban removal also refuses the endpoint readmission. A removal that is
// not a ban - a member that went quiet, or that asked to leave - leaves
// it free to come back, which is what makes a netsplit recoverable.
func (s *sealed) evict(ctx context.Context, id key.EndpointID, ban bool) error {
	s.sending.Lock()
	defer s.sending.Unlock()
	s.mu.Lock()
	if ban {
		// Recorded before the commit, and the whole kick fails if it
		// cannot be: a member removed from the group but missing from
		// the ban list is one the next restart lets back in, which is
		// the failure this is here to prevent.
		if err := s.state.ban(s.ch.name, id); err != nil {
			s.mu.Unlock()
			return fmt.Errorf("record ban on %v: %w", id.Short(), err)
		}
		s.ban(id)
	}
	var proposals []*mls.Proposal
	for _, i := range mlsiroh.Leaves(s.group.Tree, id) {
		proposals = append(proposals, &mls.Proposal{
			Type:   mls.ProposalTypeRemove,
			Remove: &mls.Remove{Removed: uint32(i)},
		})
	}
	if len(proposals) == 0 {
		s.mu.Unlock()
		return nil
	}
	next, commit, _, err := s.group.Commit(proposals)
	s.mu.Unlock()
	if err != nil {
		return fmt.Errorf("removing %v from %s: %w", id.Short(), s.ch.name, err)
	}
	out, err := s.publish(ctx, commit, next)
	if err != nil {
		return fmt.Errorf("publishing the removal for %s: %w", s.ch.name, err)
	}
	// The founder does not receive its own commit back, so the removal
	// reaches its own reader here or nowhere. Every other member learns
	// it from the commit, through [sealed.commit].
	for _, ev := range out {
		if ban && ev.From.ID == id {
			ev.Text = "kicked"
		}
		s.ch.emit(ev)
	}
	return nil
}

// rotate proposes new keys for this node's own leaf and gossips the
// proposal. Every member calls it, the founder included.
//
// MLS gives forward secrecy within an epoch on its own, but post-
// compromise security only when a member's leaf keys actually change:
// an attacker who copies a member's state reads everything that member
// reads until the leaf that state belongs to is replaced. Joining and
// leaving are the only things that changed a leaf on this channel
// before now, so a channel with a settled roster never recovered from a
// compromise at all. Rotation is what makes epochs mean something for a
// member that neither joins nor leaves.
//
// The proposal replaces both encryption and signature keys. The endpoint
// key binds the new signature key to the same identity. MLS activates
// the private keys only when the founder's commit accepts the update.
// This does not recover from compromise of the endpoint key itself.
//
// The founder commits. A member that rotates while the founder is gone
// has proposed something nobody will apply, which costs it a message
// and leaves the group exactly as it was.
func (s *sealed) rotate(ctx context.Context) error {
	b, err := s.proposeRotation()
	if err != nil {
		return err
	}
	if err := s.ch.topic.Broadcast(ctx, b); err != nil {
		return fmt.Errorf("publishing the rotation for %s: %w", s.ch.name, err)
	}
	return nil
}

// proposeRotation returns the encoded update proposal that [sealed.rotate]
// publishes.
func (s *sealed) proposeRotation() ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.group == nil {
		return nil, fmt.Errorf("%s: not yet welcomed", s.ch.name)
	}
	leaf := s.group.Tree.Leaf(s.group.Index)
	if leaf == nil {
		return nil, fmt.Errorf("%s: no leaf at index %d", s.ch.name, s.group.Index)
	}
	encPriv, encPub, err := s.group.CipherSuite.GenerateKeyPair()
	if err != nil {
		return nil, fmt.Errorf("rotating keys for %s: %w", s.ch.name, err)
	}
	sigPriv, sigPub, err := s.group.CipherSuite.GenerateSignatureKeyPair()
	if err != nil {
		return nil, fmt.Errorf("rotating signing keys for %s: %w", s.ch.name, err)
	}
	next := *leaf
	next.EncryptionKey, next.SignatureKey = encPub, sigPub
	if err := mlsiroh.SignUpdate(s.sk, sigPriv, &next, s.group.Context.GroupID, s.group.Index); err != nil {
		return nil, fmt.Errorf("signing the rotation for %s: %w", s.ch.name, err)
	}
	msg, err := s.group.ProposeUpdateKeys(&next, encPriv, sigPriv)
	if err != nil {
		return nil, fmt.Errorf("proposing the rotation for %s: %w", s.ch.name, err)
	}
	b, err := mls.Marshal(msg)
	if err != nil {
		return nil, fmt.Errorf("encoding the rotation for %s: %w", s.ch.name, err)
	}
	return b, nil
}

// flush commits the proposals members have staged since the last
// commit. It is a no-op for other members and with nothing
// staged: a commit costs every member an epoch, and an epoch that
// applies nothing is a message that can only lose those who miss it.
//
// What is staged is decided by mls, which leaves out a proposal it
// cannot commit, so the commit is made and then dropped if it carries
// nothing.
func (s *sealed) flush(ctx context.Context) error {
	if !s.isFounder() {
		return nil
	}
	s.sending.Lock()
	defer s.sending.Unlock()
	s.mu.Lock()
	if s.group == nil || len(s.pending) == 0 {
		s.mu.Unlock()
		return nil
	}
	next, commit, _, err := s.group.Commit(nil)
	carried := err == nil && rotated(s.group, next, s.pending)
	s.mu.Unlock()
	if err != nil {
		return fmt.Errorf("committing rotations on %s: %w", s.ch.name, err)
	}
	if !carried {
		return nil
	}
	out, err := s.publish(ctx, commit, next)
	if err != nil {
		return fmt.Errorf("publishing the rotations for %s: %w", s.ch.name, err)
	}
	for _, ev := range out {
		s.ch.emit(ev)
	}
	return nil
}

// rotated reports whether next, the state a commit of g begins, gives
// any leaf in pending a new encryption key: that is, whether the commit
// carried an update staged for it. mls refuses an update that keeps the
// leaf's key, and a commit's own path changes only its committer's
// leaf, so this is exact for a commit with no proposals of its own. It
// is read from the states rather than from the commit, which is
// encrypted.
func rotated(g, next *mls.Group, pending map[mls.LeafIndex]bool) bool {
	for i := range pending {
		if i == g.Index {
			continue
		}
		was, now := g.Tree.Leaf(i), next.Tree.Leaf(i)
		if was != nil && now != nil && !bytes.Equal(was.EncryptionKey, now.EncryptionKey) {
			return true
		}
	}
	return false
}

// ban records id in memory. The caller holds s.mu, or holds the seal
// before anything else can see it.
func (s *sealed) ban(id key.EndpointID) {
	if s.banned == nil {
		s.banned = make(map[key.EndpointID]bool)
	}
	s.banned[id] = true
}

// admissible reports whether the founder will readmit id. A removal that
// was a ban is durable; nothing else is.
func (s *sealed) admissible(id key.EndpointID) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return !s.banned[id]
}

// mayResync reports whether enough time has passed since the last rejoin
// attempt, and records this one. It is the rate limit that keeps an
// unauthenticated epoch from costing the founder a commit per packet.
func (s *sealed) mayResync(now time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	every := s.resyncEvery
	if every == 0 {
		every = presenceInterval
	}
	if now.Sub(s.lastResync) < every {
		return false
	}
	s.lastResync = now
	return true
}

// adopt replaces the group state, on joining and after a rejoin. What
// this node said while it was behind was sealed in an epoch nobody else
// still holds, so it goes again.
func (s *sealed) adopt(client *mls.Client, g *mls.Group) []Event {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.client, s.group, s.removed = client, g, false
	return s.advanced(time.Now())
}

// reseats reports whether commit adds a leaf for this node: the founder
// seating it again after it lost its group state, which is not a
// removal from the channel and which no other member treats as one.
func (s *sealed) reseats(commit *mls.Commit) bool {
	if commit == nil {
		return false
	}
	self := s.ch.node.ID()
	for _, p := range commit.Proposals {
		if p.Type != mls.ProposalOrRefTypeProposal || p.Proposal == nil || p.Proposal.Add == nil {
			continue
		}
		if id, err := mlsiroh.VerifyLeaf(&p.Proposal.Add.KeyPackage.LeafNode); err == nil && id == self {
			return true
		}
	}
	return false
}

// wasRemoved reports whether a commit from the founder removed this
// node since it was last seated.
func (s *sealed) wasRemoved() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.removed
}

// found seats the founder in the group it just made, with its admission
// policy. The channel is registered, and so reachable by the invite
// handler, before it is seated; see [Node.admit].
func (s *sealed) found(client *mls.Client, g *mls.Group, allow func(key.EndpointID) bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.allow = allow
	s.client, s.group = client, g
	s.advanced(time.Now())
}

// admits reports whether the founder's policy admits id, and false
// when the founder is not yet seated. The policy is caller code, so it
// is called without s.mu held.
func (s *sealed) admits(id key.EndpointID) bool {
	s.mu.Lock()
	seated, allow := s.group != nil, s.allow
	s.mu.Unlock()
	return seated && (allow == nil || allow(id))
}
