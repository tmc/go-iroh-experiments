package irciroh

import (
	"context"
	"errors"
	"fmt"
	"io"
	"slices"
	"sync"
	"time"

	"github.com/tmc/go-iroh/iroh"
	"github.com/tmc/go-iroh/key"
	"github.com/tmc/go-iroh/netaddr"
	"github.com/tmc/go-iroh/postcard"
)

// A channel has no history. Gossip delivers what is said while you are
// listening and nothing else, so a member that joins at noon has no way
// to learn what was said at eleven - which is IRC's model, and is fine
// for a person who was there and knows they were not. It is not fine
// for a program, which joins, restarts, and joins again, and cannot
// tell an empty channel from one it arrived late to.
//
// Recall is the smallest thing that closes that: a joiner dials one
// member and asks for the recent lines it kept, and replays them into
// its own event stream. Nothing is written down - a member serves what
// it happens to still hold in memory from its own live receipt - so a
// channel nobody was in has no history, which is the truth rather than
// a gap.
//
// What a replay is worth is a separate question from what it says, and
// the two must not be confused. A served line is hearsay: it reaches
// this node because a peer chose to hand it over, and that peer chose
// which lines to hand over, in which order, and whether to leave any
// out. Three things follow, and they are the whole of the design:
//
//   - A replay arrives as [Replayed], never as [Message] or [Notice].
//     A renderer that has not been taught about history drops it rather
//     than showing hearsay as speech, which is the safe direction for
//     code nobody has updated yet.
//   - Every replayed line carries the key that signed it, in
//     [Event.From], and that signature is checked here. A peer cannot
//     put words in anybody's mouth, because it cannot sign for them.
//   - Every replayed line also carries the key that served it, in
//     [Event.Via]. What a serving peer can still do is omit, reorder,
//     and repeat, and no protocol can stop it; naming it is what lets a
//     reader weigh what it got and, if it comes to it, say who gave it
//     to them.
//
// A served line proves where it was said as well as who said it: the
// envelope names no channel, but the topic is bound into the signature,
// so a line lifted out of another channel does not verify here. What a
// serving peer can still do is omit, reorder and repeat, and [Event.Via]
// is who to weigh that against.
//
// Sealed channels serve nothing. Their plaintext exists on a member's
// machine only because MLS let that member read it, and handing it back
// out over a separate connection would put the group's words outside
// the group's key schedule, decided by whichever member was asked. A
// sealed channel's history is a question for its founder, not for this.

// HistoryALPN is the application-layer protocol name a member serves so
// that a joiner can ask what it missed. A node that wants to answer
// registers [Node.HistoryHandler] under it; a node that only asks does
// not need to.
const HistoryALPN = "irciroh/history/1"

// historyVersion is the format version of a recall exchange.
const historyVersion = 1

// The caps. A recall request is an unauthenticated stranger asking this
// node to spend memory, time and bandwidth on its behalf, so every part
// of the answer is bounded before the request is read.
const (
	// maxRecallLines is the most lines a node keeps per channel and the
	// most it will serve in one answer. Two hundred lines is a screen
	// of scrollback several times over - enough for a joiner to see
	// what the conversation is about, which is what this is for, and
	// not enough to be a transcript. It is also the memory a channel
	// costs when nobody ever asks: at most maxRecallLines envelopes,
	// bounded below by nothing and above by maxRecallBytes.
	maxRecallLines = 200

	// maxRecallBytes bounds one answer, and with it the memory one
	// channel's reel holds. The line cap alone does not: at
	// [MaxEnvelopeSize] each, two hundred lines is 800 KiB per channel,
	// which a member in twenty channels pays twenty times over. Chat
	// lines are a hundred bytes, so this binds only on a channel being
	// used to move bulk, which is the case worth binding.
	maxRecallBytes = 128 << 10

	// maxRecallAge is how old a line may be and still be served. It is
	// a bound on the reel's staleness rather than on its size: a
	// channel that saw ten lines a year ago should answer a joiner with
	// nothing rather than with last year's conversation presented as
	// what it missed.
	maxRecallAge = time.Hour

	// maxRecallServing is how many recall requests this node answers at
	// once. Each holds a stream and copies a reel, so the cost is
	// bounded per request; what is not bounded is how many a caller
	// opens. Beyond this they are refused at once rather than queued -
	// a joiner asks one peer and moves on, and making it wait behind a
	// flood would turn somebody else's abuse into this node's latency.
	maxRecallServing = 4

	// recallTimeout bounds one recall exchange, on both ends.
	recallTimeout = 15 * time.Second

	// defaultRecallLines is how many lines a join asks for. It is below
	// the channel's event buffer on purpose: a replay that by itself
	// overran the buffer would report a lag to a reader that never fell
	// behind. A caller that wants the rest asks [Channel.Recall] for it.
	defaultRecallLines = 50

	// maxRecallPeers is how many peers a join asks before giving up. A
	// second peer covers the first being gone; a third covers nothing
	// the second did not, and every one of them is a dial made while
	// the caller waits on Join.
	maxRecallPeers = 2
)

// historyRequest asks one member for a channel's recent lines. The
// requester is not named: nothing in the answer depends on who asks.
type historyRequest struct {
	Version uint8
	Channel string
	Limit   uint32
}

// historyResponse carries the lines, oldest first, each one the signed
// envelope the server received. A server with nothing to say - no such
// channel, a sealed one, a public one it has heard nothing in, or too
// many callers already - answers with no lines, and does not say which.
// That hides less than it might: an answer with lines in it says the
// server is in the channel, so a stranger who can name a public channel
// can learn whether this node is in it and has heard it speak. What
// stays hidden is the sealed channels, which serve nothing, and any
// channel this node is in but has heard nothing recent from.
type historyResponse struct {
	Version uint8
	Lines   [][]byte
}

// HistoryHandler returns the protocol handler that answers recall
// requests for the public channels this node is in. Register it under
// [HistoryALPN] on the endpoint's router.
//
// One handler holds one serving allowance, so register the same handler
// rather than calling this twice.
func (n *Node) HistoryHandler() iroh.ProtocolHandler {
	return historyHandler{node: n, serving: make(chan struct{}, maxRecallServing)}
}

type historyHandler struct {
	node *Node
	// serving is the concurrency allowance: a slot is taken for the
	// length of one answer and released after it.
	serving chan struct{}
}

func (h historyHandler) Accept(ctx context.Context, conn *iroh.Conn) error {
	for {
		stream, err := conn.AcceptStream(ctx)
		if err != nil {
			// The peer closed the connection, or the router is
			// shutting down. Neither is a failure of ours.
			return nil
		}
		go func() {
			defer stream.Close()
			_ = h.serve(stream)
		}()
	}
}

// serve reads one recall request and writes its answer.
func (h historyHandler) serve(stream recallStream) error {
	if err := stream.SetDeadline(time.Now().Add(recallTimeout)); err != nil {
		return err
	}
	b, err := io.ReadAll(io.LimitReader(stream, maxRecallRequest+1))
	if err != nil {
		return err
	}
	var req historyRequest
	if len(b) > maxRecallRequest || postcard.Unmarshal(b, &req) != nil || req.Version != historyVersion {
		return answer(stream, nil)
	}
	// The slot is held until the answer is written, which is the part
	// that waits on the caller: a caller that asks and does not read
	// would otherwise hold a stream and a copy of the reel outside the
	// allowance.
	select {
	case h.serving <- struct{}{}:
	default:
		return answer(stream, nil)
	}
	defer func() { <-h.serving }()
	return answer(stream, h.lines(req))
}

// maxRecallResponse is the largest answer accepted: the bytes a server
// is allowed to serve, plus the framing around them. Postcard prefixes
// each line and the sequence with a varint, which is three bytes for
// the sizes here; the slack is eight per line so that a server serving
// the most it may is not cut off by the reader that asked for it.
const maxRecallResponse = maxRecallBytes + 8*maxRecallLines + 16

// maxRecallRequest is the largest request accepted. A request is a
// version, a channel name and a count, and a channel name is at most 50
// bytes (see checkChannel), so anything larger is not one.
const maxRecallRequest = 128

// lines returns what this node will serve for one request, or nil.
func (h historyHandler) lines(req historyRequest) [][]byte {
	c, ok := h.node.Channel(req.Channel)
	if !ok || c.seal != nil {
		return nil
	}
	limit := min(int(req.Limit), maxRecallLines)
	if limit <= 0 {
		return nil
	}
	return c.recall.recent(limit, time.Now())
}

// A recallStream is what one recall exchange needs of an [iroh.Stream].
type recallStream interface {
	io.ReadWriter
	CloseWrite() error
	SetDeadline(time.Time) error
}

// answer writes one response and closes the write side.
func answer(stream recallStream, lines [][]byte) error {
	b, err := postcard.Marshal(historyResponse{Version: historyVersion, Lines: lines})
	if err != nil {
		return err
	}
	if _, err := stream.Write(b); err != nil {
		return err
	}
	return stream.CloseWrite()
}

// ErrNoHistory reports a peer that answered a recall request with
// nothing this node could use.
var ErrNoHistory = errors.New("peer served no usable history")

// Recall asks one peer for the channel's recent lines and replays what
// it serves into the channel's event stream, as [Replayed] events. It
// returns how many it replayed.
//
// A replayed line is hearsay, and stays marked as such: the package
// documentation's History section says what is checked and what cannot
// be. The replay does not touch the channel's state - not the member
// table, not the sequence numbers, not the topic - because none of it is
// this peer's to set. It is told to the reader and nothing else.
//
// from must address a peer; the connection's authenticated identity is
// checked against it, so the [Event.Via] on every replayed line names
// the endpoint that actually served it.
func (c *Channel) Recall(ctx context.Context, from netaddr.EndpointAddr, limit int) (int, error) {
	if c.seal != nil {
		return 0, fmt.Errorf("recall %s: %w", c.name, ErrNotSealed)
	}
	limit = min(max(limit, 1), maxRecallLines)
	lines, err := c.node.askHistory(ctx, c.name, from, limit)
	if err != nil {
		return 0, err
	}
	now := time.Now()
	domain := c.domain()
	c.mu.Lock()
	via := c.snapshot(from.ID)
	c.mu.Unlock()
	type said struct {
		from key.EndpointID
		seq  uint64
	}
	n, dropped := 0, 0
	seen := make(map[said]bool)
	for _, b := range lines {
		e, ok := replayable(b, domain, now)
		if !ok {
			dropped++
			continue
		}
		// A peer repeating one line to fill an answer is caught by
		// the line's sender and sequence number, which name it. The
		// set is per answer: this says nothing about what arrived
		// live, which is a different claim by a different sender.
		// It is not the live path's window, because a served line is
		// old by design and the order it is served in is the server's.
		id := said{e.sender(), e.Seq}
		if seen[id] {
			dropped++
			continue
		}
		seen[id] = true
		// A sender this node has muted stays muted in the past tense.
		// It is not counted against the server, which served a line
		// that verifies; the choice not to hear it is this node's.
		if c.node.quiet != nil && c.node.quiet(e.sender()) {
			continue
		}
		c.emit(Event{
			Kind: Replayed,
			Was:  eventKind(kind(e.Kind)),
			From: Member{ID: e.sender(), Nick: e.Nick},
			Via:  via,
			Text: e.Text,
			Time: e.at(),
		})
		n++
	}
	if dropped > 0 {
		// A reader that is shown twelve lines cannot tell that fifty
		// were offered, so a peer serving what this node will not
		// replay - lines that do not verify, lines from another
		// channel, one line repeated to fill the answer - looks
		// exactly like a peer that had little to say. Say which it
		// was, once and with a count: one event per dropped line
		// would let a bad answer fill the channel with complaints
		// about itself, which is the rule the rate limit's first
		// refusal follows for the same reason.
		c.emit(Event{
			Kind: Refused,
			From: via,
			Text: fmt.Sprintf("served %d of %d history lines this node would not replay", dropped, len(lines)),
			Time: now,
		})
	}
	if n == 0 {
		return 0, fmt.Errorf("recall %s from %v: %w", c.name, from.ID.Short(), ErrNoHistory)
	}
	return n, nil
}

// replayable reports whether one served record is worth replaying, and
// returns the envelope it holds.
//
// The signature is the part that matters: it is what keeps a serving
// peer to lines that were really said, by the keys they name, in this
// channel - the topic is bound into the signature, so a line lifted out
// of another channel does not verify here. The rest
// is housekeeping - speech only, nothing from the future, nothing older
// than the server was allowed to serve - so that a peer cannot use the
// answer to say things the live path would have refused.
func replayable(b []byte, domain [32]byte, now time.Time) (envelope, bool) {
	e, err := decode(b, domain)
	if err != nil {
		return envelope{}, false
	}
	switch kind(e.Kind) {
	case kindMessage, kindNotice:
	default:
		return envelope{}, false
	}
	if !e.fresh(now) || e.at().Before(now.Add(-maxRecallAge)) {
		return envelope{}, false
	}
	return e, true
}

// eventKind returns the event a wire kind is reported as.
func eventKind(k kind) EventKind {
	if k == kindNotice {
		return Notice
	}
	return Message
}

// askHistory runs one recall exchange against one address.
func (n *Node) askHistory(ctx context.Context, channel string, addr netaddr.EndpointAddr, limit int) ([][]byte, error) {
	req, err := postcard.Marshal(historyRequest{
		Version: historyVersion,
		Channel: channel,
		Limit:   uint32(limit),
	})
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, recallTimeout)
	defer cancel()
	conn, err := n.ep.Connect(ctx, addr, HistoryALPN)
	if err != nil {
		return nil, fmt.Errorf("dial %v: %w", addr.ID.Short(), err)
	}
	defer conn.Close()
	if conn.RemoteID() != addr.ID {
		return nil, fmt.Errorf("dial %v: %w", addr.ID.Short(), ErrPeer)
	}
	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		return nil, err
	}
	defer stream.Close()
	if deadline, ok := ctx.Deadline(); ok {
		_ = stream.SetDeadline(deadline)
	}
	if _, err := stream.Write(req); err != nil {
		return nil, err
	}
	if err := stream.CloseWrite(); err != nil {
		return nil, err
	}
	// The read is bounded by what this node asked for rather than by
	// what the server says it is sending, so an answer larger than the
	// caps allow is refused before it is parsed.
	b, err := io.ReadAll(io.LimitReader(stream, maxRecallResponse+1))
	if err != nil {
		return nil, err
	}
	lines, err := decodeHistoryResponse(b)
	if err != nil {
		return nil, err
	}
	if len(lines) > limit {
		lines = lines[:limit]
	}
	return lines, nil
}

// decodeHistoryResponse parses a recall answer and returns the lines it
// serves, each still to be checked by [replayable].
func decodeHistoryResponse(b []byte) ([][]byte, error) {
	var resp historyResponse
	if len(b) > maxRecallResponse || postcard.Unmarshal(b, &resp) != nil || resp.Version != historyVersion {
		return nil, errors.New("malformed history response")
	}
	return resp.Lines, nil
}

// recallOnJoin asks the peers a join was given for what the channel has
// been saying, stopping at the first that answers. Failure is not a
// failure of the join: a channel whose peers keep nothing, or keep it
// from strangers, is a channel with no history, and that is a thing a
// member lives with rather than an error it reports.
func (c *Channel) recallOnJoin(peers []netaddr.EndpointAddr) {
	ctx, cancel := context.WithTimeout(c.node.ctx, recallTimeout)
	defer cancel()
	asked := 0
	for _, addr := range withoutSelf(peers, c.node.ID()) {
		if len(addr.Addrs()) == 0 && len(addr.RelayURLs()) == 0 {
			continue
		}
		if asked++; asked > maxRecallPeers {
			return
		}
		if _, err := c.Recall(ctx, addr, defaultRecallLines); err == nil {
			return
		}
	}
}

// WithHistory makes this node both halves of recall: it asks the peers
// a join names for what it missed, and it keeps what it hears so it can
// answer the same question for somebody else.
//
// It is off by default because both halves are things a node does on
// other people's behalf. Asking dials a peer during the join and
// replays what comes back; keeping holds a channel's recent lines in
// memory whether or not anyone ever asks for them. Neither is free, and
// a node that only wants to listen should not pay for either.
//
// Registering [Node.HistoryHandler] under [HistoryALPN] is the other
// half of answering: without it this node keeps lines that nobody can
// reach.
func WithHistory() Option {
	return func(n *Node) error {
		n.history = true
		return nil
	}
}

// A reel is the recent speech of one public channel, in the order this
// node received it, kept so a member that arrives later can be told
// what it missed. The zero value is an empty reel, which is what a
// channel has until it hears something.
//
// What is kept is the signed envelope exactly as it arrived, not the
// text out of it. A reel that held text would be this node's word for
// what was said; holding the envelope means the signature travels with
// it, and the next member can check the speaker for itself instead of
// taking this node's word for anything.
type reel struct {
	mu    sync.Mutex
	lines []recalled
	bytes int
}

// A recalled line is one envelope and the local time it arrived.
//
// The age cap is measured against that rather than against the stamp
// inside the envelope, because how stale this node's reel has become is
// a question about this node's clock, and because receipt order is then
// the same as age order and [reel.recent] can stop at the first line
// too old. The sender's stamp is checked too, but on the other side:
// see [replayable].
type recalled struct {
	b  []byte
	at time.Time
}

// keep records one envelope, dropping the oldest lines to stay within
// the caps. b must not be modified afterwards.
func (r *reel) keep(b []byte, at time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.lines = append(r.lines, recalled{b: b, at: at})
	r.bytes += len(b)
	for len(r.lines) > maxRecallLines || r.bytes > maxRecallBytes {
		r.bytes -= len(r.lines[0].b)
		r.lines = r.lines[1:]
	}
}

// recent returns up to limit of the newest lines within [maxRecallAge]
// of now, oldest first.
func (r *reel) recent(limit int, now time.Time) [][]byte {
	r.mu.Lock()
	defer r.mu.Unlock()
	cutoff := now.Add(-maxRecallAge)
	out := make([][]byte, 0, min(limit, len(r.lines)))
	size := 0
	for i := len(r.lines) - 1; i >= 0 && len(out) < limit; i-- {
		line := r.lines[i]
		if line.at.Before(cutoff) {
			// The reel is in receipt order, so everything before
			// this is older still.
			break
		}
		if size+len(line.b) > maxRecallBytes {
			break
		}
		size += len(line.b)
		out = append(out, line.b)
	}
	slices.Reverse(out)
	return out
}
