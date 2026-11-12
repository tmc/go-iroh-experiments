package irciroh

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/tmc/go-iroh-experiments/mlsiroh"
	"github.com/tmc/go-iroh/iroh"
	"github.com/tmc/go-iroh/key"
	"github.com/tmc/go-iroh/netaddr"
	"github.com/tmc/go-iroh/postcard"
	"github.com/tmc/mls"
)

// InviteALPN is the application-layer protocol name a founder serves so
// that a node holding a [Ticket] can be let into a sealed channel. A
// node that founds sealed channels registers [Node.InviteHandler] under
// it; a node that only joins them does not need to.
const InviteALPN = "irciroh/invite/1"

// maxInvite is the largest invite response accepted. A welcome and a
// ratchet tree are both larger than an IRC line and both grow with the
// membership, so this is not [MaxEnvelopeSize].
const maxInvite = 1 << 20

// maxInviteRequest is the largest invite request a founder reads. A
// request is a channel name, a secret and one key package, none of
// which grow with the membership, so a founder has no reason to buffer
// a response's worth of bytes from anybody who can dial it.
const maxInviteRequest = 4 << 10

// maxInviting bounds the invite streams a founder serves at once. Every
// one it serves may end in a commit, and a stream over the bound is
// refused at the door rather than queued behind them.
const maxInviting = 8

// inviteTimeout bounds one invite exchange.
const inviteTimeout = 30 * time.Second

// Errors reported by the invite protocol.
var (
	// ErrNotFounder reports a join sent to a node that does not found
	// the named channel.
	ErrNotFounder = errors.New("not the founder of that channel")

	// ErrNotInvited reports a join the founder refused. The refusal
	// carries no reason, so this is every one of them: a secret that
	// does not match, an endpoint the founder banned or its policy does
	// not admit, a key package it would not take, and a founder too busy
	// to answer: past its rate limit, or restarted and not yet founding
	// the channel again. Only the first three are final.
	ErrNotInvited = errors.New("not invited to that channel")

	// ErrNotSealed reports an operation that only a sealed channel has.
	ErrNotSealed = errors.New("channel is not sealed")
)

// inviteVersion is the format version of an invite exchange.
const inviteVersion = 1

// inviteRequest asks a founder for admission to one sealed channel. The
// requester is not named: the founder reads it from the connection.
type inviteRequest struct {
	Version uint8
	Channel string
	Secret  []byte
	// KeyPackage is an encoded mls.Message carrying the joiner's
	// key package. The founder checks that its binding names the
	// endpoint that dialed, which is what makes pushing it safe:
	// a key package presented over a connection nobody else can make
	// is stronger evidence than one fetched from a directory.
	KeyPackage []byte
}

// inviteResponse is the founder's answer. A refusal carries a status and
// nothing else, and does not distinguish a channel the founder does not
// have from one the caller may not join.
type inviteResponse struct {
	Version uint8
	OK      bool
	// Welcome is an encoded mls.Message carrying the welcome, and
	// Tree the group's ratchet tree at the epoch the welcome names.
	// The tree is verified against the welcome's group context, so it
	// is carried rather than trusted.
	Welcome []byte
	Tree    []byte
}

// InviteHandler returns the protocol handler that lets holders of a
// channel's ticket into the sealed channels this node founded. Register
// it under [InviteALPN] on the endpoint's router.
func (n *Node) InviteHandler() iroh.ProtocolHandler { return inviteHandler{n} }

type inviteHandler struct{ node *Node }

func (h inviteHandler) Accept(ctx context.Context, conn *iroh.Conn) error {
	// The invite decision is written in endpoint ids, so it cannot be
	// made until the handshake has proved one. A 0-RTT connection has
	// not.
	select {
	case <-conn.HandshakeComplete():
	case <-ctx.Done():
		return ctx.Err()
	case <-conn.Context().Done():
		return conn.Context().Err()
	}
	from := conn.RemoteID()
	for {
		stream, err := conn.AcceptStream(ctx)
		if err != nil {
			// The peer closed the connection, or the router is
			// shutting down. Neither is a failure of ours.
			return nil
		}
		select {
		case h.node.inviting <- struct{}{}:
		default:
			stream.CancelRead(0)
			_ = stream.Close()
			continue
		}
		go func() {
			defer func() { <-h.node.inviting }()
			defer stream.Close()
			_ = h.serve(ctx, from, stream)
		}()
	}
}

// serve reads one invite request and writes its response.
func (h inviteHandler) serve(ctx context.Context, from key.EndpointID, stream *iroh.Stream) error {
	if err := stream.SetDeadline(time.Now().Add(inviteTimeout)); err != nil {
		return err
	}
	// Charged before anything is read, so that what an endpoint can
	// make this node do is bounded whatever it sends.
	if !h.node.mayAsk(from, time.Now()) {
		return reply(stream, inviteResponse{Version: inviteVersion})
	}
	b, err := io.ReadAll(io.LimitReader(stream, maxInviteRequest+1))
	if err != nil {
		return err
	}
	req, err := decodeInviteRequest(b)
	if err != nil {
		return reply(stream, inviteResponse{Version: inviteVersion})
	}
	welcome, tree, err := h.node.admit(ctx, from, req)
	if err != nil {
		// The refusal says only that it was refused. Which channels
		// this node founds, and who may join them, are both things
		// a caller learns by being let in.
		return reply(stream, inviteResponse{Version: inviteVersion})
	}
	return reply(stream, inviteResponse{Version: inviteVersion, OK: true, Welcome: welcome, Tree: tree})
}

// mayAsk charges one invite request to from at now and reports whether
// it may be served.
//
// A request that passes costs the founder a commit, and a ticket
// holder could otherwise ask in a loop. The charge is the presence
// allowance of [budgets.spend], because asking to join is announcing
// yourself: a burst of [presenceBurst] and then one per
// [presenceRefill], which an honest joiner, asking once per join and
// again at most once per [presenceInterval] per channel when it falls
// behind, does not reach.
func (n *Node) mayAsk(from key.EndpointID, now time.Time) bool {
	n.imu.Lock()
	defer n.imu.Unlock()
	n.invites.prune(now)
	ok, _ := n.invites.spend(from, kindJoin, 0, now, false)
	return ok
}

func reply(stream *iroh.Stream, resp inviteResponse) error {
	b, err := postcard.Marshal(resp)
	if err != nil {
		return err
	}
	if _, err := stream.Write(b); err != nil {
		return err
	}
	return stream.CloseWrite()
}

// admit checks one invite request and, if it passes, commits the joiner
// into the channel.
func (n *Node) admit(ctx context.Context, from key.EndpointID, req *inviteRequest) (welcome, tree []byte, err error) {
	c, ok := n.Channel(req.Channel)
	if !ok || c.seal == nil {
		return nil, nil, ErrNotFounder
	}
	s := c.seal
	if !s.isFounder() {
		return nil, nil, ErrNotFounder
	}
	if subtle.ConstantTimeCompare(req.Secret, s.invite) != 1 {
		return nil, nil, ErrNotInvited
	}
	// A removal that was a ban outlives the commit that made it. The
	// invite secret does not name anyone, so without this check the
	// endpoint just removed presents it again and is let back in.
	if !s.admissible(from) {
		c.emit(Event{Kind: Refused, From: Member{ID: from}, Text: "banned", Time: time.Now()})
		return nil, nil, ErrNotInvited
	}
	if !s.admits(from) {
		c.emit(Event{Kind: Refused, From: Member{ID: from}, Text: "not allowed", Time: time.Now()})
		return nil, nil, ErrNotInvited
	}

	kp, id, err := verifyKeyPackage(req.KeyPackage, time.Now())
	if err != nil {
		return nil, nil, err
	}
	// The whole authentication: the key package's binding names an
	// endpoint, and the transport already proved which endpoint is
	// on the other end of this stream. They must be the same one.
	if id != from {
		return nil, nil, fmt.Errorf("key package names %v, dialed by %v: %w", id.Short(), from.Short(), ErrNotInvited)
	}

	w, rt, events, err := s.admit(ctx, kp, from)
	if err != nil {
		return nil, nil, err
	}
	wb, err := mls.Marshal(&mls.Message{Version: mls.Version10, WireFormat: mls.WireFormatWelcome, Welcome: w})
	if err != nil {
		return nil, nil, err
	}
	tb, err := mls.Marshal(&rt)
	if err != nil {
		return nil, nil, err
	}
	for _, ev := range events {
		c.emit(ev)
	}
	return wb, tb, nil
}

// ask sends one invite request to the founder and returns the client it
// minted along with the group it was welcomed into.
func (n *Node) ask(ctx context.Context, t Ticket, addrs []netaddr.EndpointAddr) (*mls.Client, *mls.Group, error) {
	client, err := mlsiroh.NewClient(n.secret(), keyPackageLifetime)
	if err != nil {
		return nil, nil, err
	}
	kpb, err := mls.Marshal(&mls.Message{
		Version:    mls.Version10,
		WireFormat: mls.WireFormatKeyPackage,
		KeyPackage: client.KeyPackage,
	})
	if err != nil {
		return nil, nil, err
	}
	req, err := postcard.Marshal(inviteRequest{
		Version:    inviteVersion,
		Channel:    t.Channel,
		Secret:     t.Secret,
		KeyPackage: kpb,
	})
	if err != nil {
		return nil, nil, err
	}

	// Only the founder admits. A ticket minted by another member may
	// carry no address for it, and then the founder is dialed by id,
	// which the endpoint resolves as it would any other peer.
	var founder []netaddr.EndpointAddr
	for _, addr := range addrs {
		if addr.ID == t.Founder {
			founder = append(founder, addr)
		}
	}
	if len(founder) == 0 {
		founder = append(founder, n.PeerAddr(t.Founder))
	}
	var last error
	for _, addr := range founder {
		resp, err := n.exchange(ctx, addr, req)
		if err != nil {
			last = err
			continue
		}
		if !resp.OK {
			return nil, nil, fmt.Errorf("join %s: %w", t.Channel, ErrNotInvited)
		}
		w, tree, err := resp.welcome()
		if err != nil {
			return nil, nil, fmt.Errorf("join %s: %w", t.Channel, err)
		}
		// Join verifies the tree against the welcome's own group
		// context, so a founder that sends the wrong one is caught
		// here rather than trusted.
		g, err := client.Join(w, tree)
		if err != nil {
			return nil, nil, fmt.Errorf("join %s: %w", t.Channel, err)
		}
		return client, g, nil
	}
	return nil, nil, fmt.Errorf("join %s: %w", t.Channel, last)
}

// exchange runs one invite request, refreshing failed address hints before
// sending any request bytes.
func (n *Node) exchange(ctx context.Context, addr netaddr.EndpointAddr, req []byte) (*inviteResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, inviteTimeout)
	defer cancel()
	dialCtx := ctx
	stopDial := func() {}
	if !addr.IsEmpty() {
		// A ticket's address hints can outlive the founder's relay or UDP
		// address. Leave half the remaining exchange budget for ID lookup.
		deadline, _ := ctx.Deadline()
		dialCtx, stopDial = context.WithTimeout(ctx, time.Until(deadline)/2)
	}
	conn, err := n.ep.Connect(dialCtx, addr, InviteALPN)
	stopDial()
	if err != nil && !addr.IsEmpty() && ctx.Err() == nil {
		// Connect only looks up an address when no hints were supplied.
		// No request bytes have been sent, so this cannot repeat admission.
		conn, err = n.ep.Connect(ctx, netaddr.NewEndpointAddr(addr.ID), InviteALPN)
	}
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
	b, err := io.ReadAll(io.LimitReader(stream, maxInvite+1))
	if err != nil {
		return nil, err
	}
	return decodeInviteResponse(b)
}

// decodeInviteRequest parses one invite request.
func decodeInviteRequest(b []byte) (*inviteRequest, error) {
	var req inviteRequest
	if len(b) > maxInviteRequest || postcard.Unmarshal(b, &req) != nil || req.Version != inviteVersion {
		return nil, errors.New("malformed invite request")
	}
	return &req, nil
}

// verifyKeyPackage parses the key package an invite request carries and
// returns it with the endpoint its binding names.
func verifyKeyPackage(b []byte, now time.Time) (*mls.KeyPackage, key.EndpointID, error) {
	var msg mls.Message
	if err := mls.Unmarshal(b, &msg); err != nil {
		return nil, key.EndpointID{}, fmt.Errorf("decode key package: %w", err)
	}
	if msg.WireFormat != mls.WireFormatKeyPackage || msg.KeyPackage == nil {
		return nil, key.EndpointID{}, errors.New("invite carried no key package")
	}
	id, err := mlsiroh.Verify(msg.KeyPackage, now)
	if err != nil {
		return nil, key.EndpointID{}, fmt.Errorf("verify key package: %w", err)
	}
	return msg.KeyPackage, id, nil
}

// decodeInviteResponse parses one invite response.
func decodeInviteResponse(b []byte) (*inviteResponse, error) {
	var resp inviteResponse
	if len(b) > maxInvite || postcard.Unmarshal(b, &resp) != nil || resp.Version != inviteVersion {
		return nil, errors.New("malformed invite response")
	}
	return &resp, nil
}

// welcome parses the Welcome and ratchet tree an accepting response
// carries. Neither is verified here: [mls.Client.Join] checks both.
func (resp *inviteResponse) welcome() (*mls.Welcome, mls.RatchetTree, error) {
	var msg mls.Message
	if err := mls.Unmarshal(resp.Welcome, &msg); err != nil {
		return nil, nil, fmt.Errorf("decode welcome: %w", err)
	}
	if msg.WireFormat != mls.WireFormatWelcome || msg.Welcome == nil {
		return nil, nil, errors.New("response carried no welcome")
	}
	var tree mls.RatchetTree
	if err := mls.Unmarshal(resp.Tree, &tree); err != nil {
		return nil, nil, fmt.Errorf("decode ratchet tree: %w", err)
	}
	return msg.Welcome, tree, nil
}

// resync rejoins a sealed channel whose epoch this node has fallen
// behind. It is the same exchange as the original join, because it is
// the same problem: this node holds no usable group state and the
// founder must give it one. See sealed.
//
// The founder never resyncs: its group state is the one everybody else
// catches up to, and asking would be dialing itself.
func (c *Channel) resync() {
	if c.seal == nil || c.seal.isFounder() {
		return
	}
	c.resyncing.Lock()
	defer c.resyncing.Unlock()
	select {
	case <-c.quit:
		return
	default:
	}
	ctx, cancel := context.WithTimeout(c.node.ctx, inviteTimeout)
	defer cancel()
	t := Ticket{Channel: c.name, Secret: c.seal.invite, Founder: c.seal.founder}
	client, g, err := c.node.ask(ctx, t, nil)
	if errors.Is(err, ErrNotInvited) && c.seal.wasRemoved() {
		// The founder removed this node and will not seat it
		// again: a kick. The channel is over for this node, and
		// saying so is better than running on in an epoch nobody
		// else is in, where everything said goes unheard.
		c.node.forget(c)
		c.emit(Event{Kind: Parted, From: Member{ID: c.node.ID(), Nick: c.node.Nick()}, Text: "removed", Time: time.Now()})
		c.shutdown()
		return
	}
	if err != nil {
		// The next message from an epoch ahead tries again. A
		// channel whose founder is unreachable stays where it is,
		// which is the honest outcome: nobody else can seat it.
		return
	}
	for _, ev := range c.seal.adopt(client, g) {
		c.emit(ev)
	}
}
