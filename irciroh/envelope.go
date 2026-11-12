package irciroh

import (
	"errors"
	"fmt"
	"time"

	"github.com/tmc/go-iroh/key"
	"github.com/tmc/go-iroh/postcard"
)

// MaxEnvelopeSize is the largest encoded envelope sent or accepted. Longer
// text must be split by the caller, mirroring IRC's 512-byte line limit.
const MaxEnvelopeSize = 4096

// wireVersion is the envelope format version.
const wireVersion = 1

// maxClockSkew is how far a live envelope's timestamp may be from local
// time, ahead or behind, before it is dropped. Behind is also how old an
// envelope may be and still be taken as something said now; recall,
// which is explicitly about the past, has its own bound. See
// [seqSet.accept].
const maxClockSkew = 5 * time.Minute

// kind classifies an envelope. The values are wire constants.
type kind uint8

const (
	kindJoin    kind = 1
	kindPart    kind = 2
	kindPing    kind = 3
	kindMessage kind = 4
	kindNotice  kind = 5
	kindTopic   kind = 6
	kindNick    kind = 7
	kindMode    kind = 8
	kindRank    kind = 9
)

var (
	errVersion   = errors.New("unsupported envelope version")
	errSignature = errors.New("envelope signature does not verify")
)

// Errors for a line a node refuses to send. Every call that sends a nick
// or text - [Channel.Say], [Channel.Notice], [Channel.SetTopic],
// [Channel.Part], [Node.SetNick], [Node.SendPrivate] - returns an error
// wrapping one of these rather than send what every peer would drop, so
// that a caller can tell input to fix from a network to retry.
var (
	// ErrControl reports a control character, or a space in a nick.
	// Text may hold tab, IRC's formatting codes and CTCP's \x01; CR, LF,
	// NUL and the other control characters would end or split a line in
	// whatever renders it next.
	ErrControl = errors.New("control character")
	// ErrTooLarge reports a line whose encoding exceeds
	// [MaxEnvelopeSize].
	ErrTooLarge = errors.New("envelope exceeds the size limit")
)

// envelope is one signed irciroh message. The channel name is not carried:
// the gossip topic already identifies it. The topic is bound into the
// signature instead - see [envelope.signed] - so that an envelope proves
// where it was said as well as who said it.
type envelope struct {
	Version uint8
	Kind    uint8
	Sender  [32]byte
	Seq     uint64
	Time    int64
	Nick    string
	Text    string
	Sig     [64]byte
}

// signed returns the bytes covered by Sig. Sig is the final field and
// encodes as 64 raw bytes, so the signed prefix is the encoding of the
// whole envelope without its last 64 bytes.
//
// The domain goes in front of that prefix, and is the gossip topic the
// envelope is said on - or [dmDomain] for a direct message. Without it a
// signature proves only who spoke, and anybody holding the bytes could
// present a line said in one channel as a line said in another: the
// envelope names no channel, so nothing in it would disagree. Binding
// the topic makes that a signature that does not verify. It is fixed
// width, so no length prefix is needed to keep the encoding unambiguous.
func (e envelope) signed(domain [32]byte) ([]byte, error) {
	b, err := postcard.Marshal(e)
	if err != nil {
		return nil, fmt.Errorf("encode envelope: %w", err)
	}
	msg := make([]byte, 0, len(domain)+len(b)-len(e.Sig))
	msg = append(msg, domain[:]...)
	return append(msg, b[:len(b)-len(e.Sig)]...), nil
}

// encode returns the wire form of e.
func (e envelope) encode() ([]byte, error) {
	b, err := postcard.Marshal(e)
	if err != nil {
		return nil, fmt.Errorf("encode envelope: %w", err)
	}
	if len(b) > MaxEnvelopeSize {
		return nil, fmt.Errorf("encode envelope: %d bytes: %w", len(b), ErrTooLarge)
	}
	return b, nil
}

// sender returns the endpoint identity that signed e. It is valid only for
// an envelope returned by decode, which checks the key.
func (e envelope) sender() key.EndpointID {
	return key.UncheckedEndpointID(e.Sender)
}

// at returns the sender's clock reading.
func (e envelope) at() time.Time { return time.UnixMilli(e.Time) }

// fresh reports whether e's timestamp is no further ahead of now than the
// accepted skew.
func (e envelope) fresh(now time.Time) bool {
	return !e.at().After(now.Add(maxClockSkew))
}

// checkNick reports whether nick may be sent: it holds no control
// character and no space. A nick is shown beside everything its sender
// says, and nothing in it has a use there that a formatting code or a
// line break would not abuse.
func checkNick(nick string) error {
	for _, r := range nick {
		if r == ' ' || control(r) {
			return fmt.Errorf("nick %q contains %U: %w", nick, r, ErrControl)
		}
	}
	return nil
}

// checkText reports whether text may be sent as a message, a topic or
// any other envelope's body. It may carry tab, CTCP's delimiter and
// IRC's formatting codes, which are what a client puts in a line on
// purpose, and no other control character: not CR, LF or NUL, which
// would end or split a line in whatever renders it next, and not DEL or
// a C1 control.
func checkText(text string) error {
	for _, r := range text {
		switch r {
		case '\t', 0x01, 0x02, 0x03, 0x0f, 0x16, 0x1d, 0x1e, 0x1f:
			continue
		}
		if control(r) {
			return fmt.Errorf("text contains %U: %w", r, ErrControl)
		}
	}
	return nil
}

// control reports whether r is a C0 control, DEL, or a C1 control.
func control(r rune) bool { return r < 0x20 || 0x7f <= r && r < 0xa0 }

// checkLine checks the nick and text an envelope or a sealed note
// carries. See [checkNick] and [checkText].
func checkLine(nick, text string) error {
	if err := checkNick(nick); err != nil {
		return err
	}
	return checkText(text)
}

// sign returns a signed envelope of the given kind.
func sign(sk key.SecretKey, domain [32]byte, k kind, seq uint64, nick, text string) (envelope, error) {
	if err := checkLine(nick, text); err != nil {
		return envelope{}, fmt.Errorf("sign envelope: %w", err)
	}
	e := envelope{
		Version: wireVersion,
		Kind:    uint8(k),
		Sender:  sk.Public().Bytes(),
		Seq:     seq,
		Time:    time.Now().UnixMilli(),
		Nick:    nick,
		Text:    text,
	}
	msg, err := e.signed(domain)
	if err != nil {
		return envelope{}, err
	}
	e.Sig = sk.Sign(msg).Bytes()
	if _, err := e.encode(); err != nil {
		return envelope{}, err
	}
	return e, nil
}

// decode parses b and verifies its signature against domain, which is
// the topic the envelope is claimed to have been said on, and refuses an
// envelope whose nick or text [checkLine] would not send. Sequence and
// clock checks need per-sender state and are left to the caller.
func decode(b []byte, domain [32]byte) (envelope, error) {
	if len(b) > MaxEnvelopeSize {
		return envelope{}, fmt.Errorf("decode envelope: %d bytes: %w", len(b), ErrTooLarge)
	}
	var e envelope
	if err := postcard.Unmarshal(b, &e); err != nil {
		return envelope{}, fmt.Errorf("decode envelope: %w", err)
	}
	if e.Version != wireVersion {
		return envelope{}, fmt.Errorf("decode envelope: version %d: %w", e.Version, errVersion)
	}
	pub, err := key.NewPublicKey(e.Sender)
	if err != nil {
		return envelope{}, fmt.Errorf("decode envelope: sender: %w", err)
	}
	msg, err := e.signed(domain)
	if err != nil {
		return envelope{}, err
	}
	if err := pub.Verify(msg, key.NewSignature(e.Sig)); err != nil {
		return envelope{}, fmt.Errorf("decode envelope: %w", errSignature)
	}
	if err := checkLine(e.Nick, e.Text); err != nil {
		return envelope{}, fmt.Errorf("decode envelope: %w", err)
	}
	return e, nil
}

// replayWindow is how far below a sender's highest sequence number an
// envelope may arrive and still be accepted, if it has not been already.
// Gossip does not promise order - a lazy-push repair or a change in the
// tree can deliver a sender's earlier envelope after a later one - and a
// rule that took only increasing numbers dropped the earlier one without
// a word. The window is counted in the sender's numbers rather than in
// this channel's traffic, because a node numbers everything it sends
// from one counter. It is the width of [seqWindow.seen].
const replayWindow = 64

// seqIdle is how long a sender's window is kept after its last accepted
// envelope. Once it has passed, everything the window accepted is older
// than [maxClockSkew] - an envelope is accepted at most that far ahead
// of local time - so the clock refuses a replay of it without the
// window's help, and forgetting the window lets nothing back in.
const seqIdle = 2 * maxClockSkew

// seqSet tracks the sequence numbers accepted from each sender on one
// topic or one connection.
type seqSet map[key.EndpointID]*seqWindow

// A seqWindow is one sender's accepted sequence numbers: the highest, the
// [replayWindow] numbers below it as a bitmap, and when the last was
// accepted.
type seqWindow struct {
	top  uint64
	seen uint64 // bit i is top-i
	last time.Time
}

// accept reports whether an envelope from from is acceptable at local time
// now, and records its sequence number when it is. It rejects an envelope
// whose clock is more than [maxClockSkew] from now in either direction, a
// sequence number already accepted, and one too far below the highest to
// tell whether it was.
//
// The clock bound behind now is what stands between a stale envelope and
// a receiver that has never heard its sender: a member that joins has no
// windows, and without the bound anybody holding an old envelope could
// present it as said just now.
func (s seqSet) accept(from key.EndpointID, e envelope, now time.Time) bool {
	if !e.fresh(now) || e.at().Before(now.Add(-maxClockSkew)) {
		return false
	}
	w := s[from]
	switch {
	case w == nil:
		s[from] = &seqWindow{top: e.Seq, seen: 1, last: now}
		return true
	case e.Seq > w.top:
		if d := e.Seq - w.top; d < replayWindow {
			w.seen = w.seen<<d | 1
		} else {
			w.seen = 1
		}
		w.top = e.Seq
	case w.top-e.Seq >= replayWindow:
		return false
	default:
		bit := uint64(1) << (w.top - e.Seq)
		if w.seen&bit != 0 {
			return false
		}
		w.seen |= bit
	}
	w.last = now
	return true
}

// prune forgets senders not accepted from for [seqIdle].
func (s seqSet) prune(now time.Time) {
	for id, w := range s {
		if now.Sub(w.last) > seqIdle {
			delete(s, id)
		}
	}
}
