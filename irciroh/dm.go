package irciroh

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"iter"
	"time"

	"github.com/tmc/go-iroh/iroh"
	"github.com/tmc/go-iroh/key"
	"github.com/tmc/go-iroh/netaddr"

	"lukechampine.com/blake3"
)

// ALPN is the application-layer protocol name for irciroh private
// messages. A node that wants to receive them registers [Node.Handler]
// under it.
const ALPN = "irciroh/dm/1"

// ack is the single byte a receiver writes once it has accepted a frame,
// nak is what it writes instead when it cannot take it, and stale is what
// it writes for a frame it has already taken or whose clock runs too far
// ahead. A receiver that answered none of them would leave the sender
// with an EOF, which says that something went wrong and nothing about
// what.
const (
	ack   = 0x00
	nak   = 0x01
	stale = 0x02
)

// dmQueueWait is how long a receiver holds a frame at the door while its
// own reader catches up. It is short because the only thing waiting
// buys is a reader that is briefly behind: a reader that has gone away
// is not coming back, and the sender is better told so.
const dmQueueWait = 2 * time.Second

// ErrNotReading is returned when a peer accepted a private message and
// then refused it because nothing on its side was reading. It is a
// working path to a node that is not listening, which is not the same
// failure as being unable to reach it.
var ErrNotReading = errors.New("peer is not reading its private messages")

// ErrPeer is returned when a private message does not match the peer that
// sent it.
var ErrPeer = errors.New("envelope sender is not the connected peer")

// Handler returns the protocol handler for private messages. Register it
// under [ALPN] on the endpoint's router.
func (n *Node) Handler() iroh.ProtocolHandler { return dmHandler{n} }

// Private returns the stream of private messages addressed to this node,
// as events of kind [Message]. It ends when the node is closed. Only one
// reader may range over it.
func (n *Node) Private() iter.Seq2[Event, error] {
	return func(yield func(Event, error) bool) {
		for {
			select {
			case ev := <-n.private:
				if !yield(ev, nil) {
					return
				}
			case <-n.ctx.Done():
				return
			}
		}
	}
}

// SendPrivate delivers text to one peer over a direct QUIC stream and waits
// for its acknowledgement. addr must address to; the connection's
// authenticated identity is checked against it.
func (n *Node) SendPrivate(ctx context.Context, to key.EndpointID, addr netaddr.EndpointAddr, text string) error {
	if addr.ID != to {
		return fmt.Errorf("send private to %s: address is for %s", to.Short(), addr.ID.Short())
	}
	e, err := sign(n.secret(), dmDomain, kindMessage, n.nextSeq(), n.Nick(), text)
	if err != nil {
		return err
	}
	b, err := e.encode()
	if err != nil {
		return err
	}
	conn, err := n.ep.Connect(ctx, addr, ALPN)
	if err != nil {
		return fmt.Errorf("dial %s: %w", to.Short(), err)
	}
	defer conn.Close()
	if conn.RemoteID() != to {
		return fmt.Errorf("dial %s: %w", to.Short(), ErrPeer)
	}
	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		return fmt.Errorf("open stream to %s: %w", to.Short(), err)
	}
	defer stream.Close()
	if deadline, ok := ctx.Deadline(); ok {
		_ = stream.SetDeadline(deadline)
	}
	frame := binary.BigEndian.AppendUint32(nil, uint32(len(b)))
	if _, err := stream.Write(append(frame, b...)); err != nil {
		return fmt.Errorf("write private message to %s: %w", to.Short(), err)
	}
	var reply [1]byte
	if _, err := io.ReadFull(stream, reply[:]); err != nil {
		return fmt.Errorf("read ack from %s: %w", to.Short(), err)
	}
	switch reply[0] {
	case ack:
	case nak:
		return fmt.Errorf("send private to %s: %w", to.Short(), ErrNotReading)
	case stale:
		return fmt.Errorf("send private to %s: refused as stale or replayed", to.Short())
	default:
		return fmt.Errorf("read ack from %s: got %#02x", to.Short(), reply[0])
	}
	return nil
}

// dmHandler serves private-message connections for a node.
// dmDomain is what a direct message is signed against. A direct message
// is said on no topic, so it needs a domain of its own - and having one
// is also what stops an envelope sent privately from being served as
// something said in a channel, or the other way round.
var dmDomain = blake3.Sum256([]byte("irciroh/dm/v1"))

type dmHandler struct{ node *Node }

// Accept reads frames from every stream of conn until it closes.
func (h dmHandler) Accept(ctx context.Context, conn *iroh.Conn) error {
	for {
		stream, err := conn.AcceptStream(ctx)
		if err != nil {
			// The peer closed the connection or the router shut down.
			return nil
		}
		go func() {
			defer stream.Close()
			// A frame that does not verify is dropped: the sender sees
			// no acknowledgement.
			_ = h.serve(conn.RemoteID(), stream)
		}()
	}
}

// dmTimeout bounds one private-message exchange on the receiving side:
// the frame, the wait for the reader, and the reply. A sender that opens
// a stream and then says nothing would otherwise hold a goroutine here
// for as long as it kept the connection alive.
var dmTimeout = 30 * time.Second

// A frameStream is what one private-message exchange needs of an
// [iroh.Stream].
type frameStream interface {
	io.ReadWriter
	SetDeadline(time.Time) error
}

// serve reads one frame, accepts it, and acknowledges it.
func (h dmHandler) serve(peer key.EndpointID, stream frameStream) error {
	if err := stream.SetDeadline(time.Now().Add(dmTimeout)); err != nil {
		return err
	}
	buf, err := readFrame(stream)
	if err != nil {
		return err
	}
	e, err := decode(buf, dmDomain)
	if err != nil {
		return err
	}
	// QUIC already authenticated the peer, so the signature must be the
	// peer's own.
	if e.sender() != peer {
		return ErrPeer
	}
	h.node.dmu.Lock()
	ok := h.node.dmSeen.accept(peer, e, time.Now())
	h.node.dmu.Unlock()
	if !ok {
		if _, err := stream.Write([]byte{stale}); err != nil {
			return fmt.Errorf("write stale: %w", err)
		}
		return errors.New("stale or replayed frame")
	}

	ev := Event{
		Kind: Message,
		From: Member{ID: peer, Nick: e.Nick, Seen: time.Now()},
		Text: e.Text,
		Time: e.at(),
	}
	// The acknowledgement is written after the event is queued, so that
	// it means the message was taken rather than merely read off the
	// wire. A reader that has gone away would otherwise hold the sender
	// here for as long as the stream lasted, and tell it nothing.
	wait := time.NewTimer(dmQueueWait)
	defer wait.Stop()
	select {
	case h.node.private <- ev:
	case <-wait.C:
		if _, err := stream.Write([]byte{nak}); err != nil {
			return fmt.Errorf("write nak: %w", err)
		}
		return ErrNotReading
	case <-h.node.ctx.Done():
		return h.node.ctx.Err()
	}
	if _, err := stream.Write([]byte{ack}); err != nil {
		return fmt.Errorf("write ack: %w", err)
	}
	return nil
}

// readFrame reads one length-prefixed envelope: a four-byte big-endian
// size, then that many bytes, at most [MaxEnvelopeSize].
func readFrame(r io.Reader) ([]byte, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, fmt.Errorf("read frame length: %w", err)
	}
	size := binary.BigEndian.Uint32(hdr[:])
	if size == 0 || size > MaxEnvelopeSize {
		return nil, fmt.Errorf("frame of %d bytes: %w", size, ErrTooLarge)
	}
	buf := make([]byte, size)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, fmt.Errorf("read frame: %w", err)
	}
	return buf, nil
}

// dmReplay is the sequence numbers recently accepted from each peer that
// sent this node a private message.
//
// It is a window rather than a high-water mark, because each private
// message is its own stream and nothing orders two of them: a sender
// with several in flight at once delivers them in whatever order the
// streams are accepted, and a mark refused all but the first to arrive.
// A window takes them in any order and still refuses one it has seen,
// or, once full, one older than everything it remembers. See [recent].
//
// A peer is forgotten once it has been quiet for [budgetIdle], the
// same bound the rate limiter keeps. Forgetting lets a frame through
// again, but only from the peer that signed it: the stream is
// authenticated, and a frame whose signer is not the peer on the other
// end is refused before it gets here.
type dmReplay map[key.EndpointID]*dmSeen

// A dmSeen is one peer's window and when it last sent.
type dmSeen struct {
	seqs recent
	last time.Time
}

// accept reports whether an envelope from from is acceptable at now,
// and records its sequence number when it is.
func (r dmReplay) accept(from key.EndpointID, e envelope, now time.Time) bool {
	for id, x := range r {
		if now.Sub(x.last) > budgetIdle {
			delete(r, id)
		}
	}
	if !e.fresh(now) {
		return false
	}
	x := r[from]
	if x == nil {
		x = &dmSeen{}
		r[from] = x
	}
	if !x.seqs.add(e.Seq) {
		return false
	}
	x.last = now
	return true
}
