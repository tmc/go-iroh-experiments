package dtrain

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/tmc/go-iroh/gossip"
	"github.com/tmc/go-iroh/iroh"
	"github.com/tmc/go-iroh/key"
	"github.com/tmc/go-iroh/netaddr"
)

const announceEvery = 200 * time.Millisecond

// ALPN is the iroh application protocol used by dtrain collectives.
const ALPN = "/dtrain/1"

// EventKind identifies a group event.
type EventKind uint8

const (
	// Join reports a direct gossip neighbor joining the group.
	Join EventKind = iota
	// Leave reports a direct gossip neighbor leaving the group.
	Leave
	// Membership reports a changed ranked membership.
	Membership
)

// Event is a group membership event.
type Event struct {
	Kind    EventKind
	Peer    key.EndpointID
	Members []Member
}

// Member is one ranked group member.
type Member struct {
	ID   key.EndpointID
	Rank int
	Addr netaddr.EndpointAddr
}

// Group is a ranked training group backed by an iroh-gossip topic.
type Group struct {
	name  string
	ep    *iroh.Endpoint
	topic *gossip.Topic
	h     *Handler

	ctx    context.Context
	cancel context.CancelFunc
	done   chan struct{}

	mu      sync.Mutex
	members map[key.EndpointID]memberState
	ranked  []Member
	events  chan Event
	closed  bool

	seq     atomic.Uint64
	bseq    atomic.Uint64
	pending map[uint64]chan []float32
	inbound map[uint64]chan allReduceFrame
	bcast   map[uint64]chan []byte
}

type announcement struct {
	Type  string   `json:"type"`
	ID    string   `json:"id"`
	Addrs []string `json:"addrs,omitempty"`
}

type memberState struct {
	addr netaddr.EndpointAddr
	seen time.Time
}

// Handler serves dtrain stream collectives for registered groups.
type Handler struct {
	mu     sync.Mutex
	groups map[string]*Group
}

// NewHandler returns a dtrain stream protocol handler.
func NewHandler() *Handler {
	return &Handler{groups: make(map[string]*Group)}
}

// JoinGroup joins name using g and returns a ranked group handle.
func JoinGroup(ctx context.Context, ep *iroh.Endpoint, g *gossip.Gossip, name string, bootstrap []netaddr.EndpointAddr) (*Group, error) {
	return JoinGroupWithHandler(ctx, ep, g, nil, name, bootstrap)
}

// JoinGroupWithHandler joins name and registers it with h for collectives.
func JoinGroupWithHandler(ctx context.Context, ep *iroh.Endpoint, gg *gossip.Gossip, h *Handler, name string, bootstrap []netaddr.EndpointAddr) (*Group, error) {
	if ep == nil {
		return nil, errors.New("dtrain: nil endpoint")
	}
	if gg == nil {
		return nil, errors.New("dtrain: nil gossip")
	}
	if name == "" {
		return nil, errors.New("dtrain: empty group name")
	}
	topic, err := gg.Subscribe(ctx, topicID(name), bootstrap)
	if err != nil {
		return nil, fmt.Errorf("dtrain: subscribe group: %w", err)
	}
	runCtx, cancel := context.WithCancel(context.Background())
	group := &Group{
		name:    name,
		ep:      ep,
		topic:   topic,
		h:       h,
		ctx:     runCtx,
		cancel:  cancel,
		done:    make(chan struct{}),
		members: make(map[key.EndpointID]memberState),
		events:  make(chan Event, 128),
		pending: make(map[uint64]chan []float32),
		inbound: make(map[uint64]chan allReduceFrame),
		bcast:   make(map[uint64]chan []byte),
	}
	group.setMember(ep.ID(), ep.Addr(), time.Now())
	if err := group.announce(ctx); err != nil {
		_ = topic.Close()
		cancel()
		return nil, err
	}
	if h != nil {
		h.register(name, group)
	}
	go group.run()
	return group, nil
}

// Close leaves the group.
func (g *Group) Close() error {
	if g == nil {
		return nil
	}
	g.cancel()
	<-g.done
	return nil
}

// ID returns the local endpoint ID.
func (g *Group) ID() key.EndpointID {
	if g == nil || g.ep == nil {
		return key.EndpointID{}
	}
	return g.ep.ID()
}

// Members returns the current ranked membership.
func (g *Group) Members() []Member {
	if g == nil {
		return nil
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	return slices.Clone(g.ranked)
}

// Rank returns the local rank, or -1 if the local endpoint is not a member.
func (g *Group) Rank() int {
	if g == nil {
		return -1
	}
	id := g.ID()
	g.mu.Lock()
	defer g.mu.Unlock()
	for _, m := range g.ranked {
		if m.ID == id {
			return m.Rank
		}
	}
	return -1
}

// Events returns the group event stream. The stream ends after Close.
func (g *Group) Events() <-chan Event {
	if g == nil {
		return nil
	}
	return g.events
}

func (g *Group) run() {
	defer close(g.done)
	defer close(g.events)
	defer func() {
		if g.h != nil {
			g.h.unregister(g.name, g)
		}
		g.mu.Lock()
		g.closed = true
		g.mu.Unlock()
		_ = g.topic.Close()
	}()

	go g.announceLoop()
	// Events blocks and yields events until the topic channel closes (the group
	// is closed, or gossip dropped the subscriber after a Lagged overflow), at
	// which point the range ends and run returns. Ranging once — rather than
	// re-entering Events after each event — avoids a hot spin once the channel
	// is closed and drained.
	for ev, err := range g.topic.Events() {
		if err != nil {
			g.emit(Event{Kind: Leave})
			return
		}
		g.handle(ev)
	}
}

func (g *Group) announceLoop() {
	tick := time.NewTicker(announceEvery)
	defer tick.Stop()
	for {
		select {
		case <-g.ctx.Done():
			_ = g.topic.Close()
			return
		case <-tick.C:
			_ = g.announce(context.Background())
		}
	}
}

func (g *Group) handle(ev gossip.Event) {
	switch ev.Kind {
	case gossip.NeighborUp:
		g.setMember(ev.Peer, netaddr.NewEndpointAddr(ev.Peer), time.Now())
		g.emit(Event{Kind: Join, Peer: ev.Peer, Members: g.Members()})
		_ = g.announce(context.Background())
	case gossip.NeighborDown:
		g.removeMember(ev.Peer)
		g.emit(Event{Kind: Leave, Peer: ev.Peer, Members: g.Members()})
	case gossip.Received:
		var a announcement
		if err := json.Unmarshal(ev.Content, &a); err == nil && a.Type == "dtrain.join" {
			id, err := key.ParseEndpointID(a.ID)
			if err != nil {
				return
			}
			addr, err := announcementAddr(id, a.Addrs)
			if err != nil {
				return
			}
			g.setMember(id, addr, time.Now())
			return
		}
		var b broadcastMessage
		if err := json.Unmarshal(ev.Content, &b); err == nil && b.Type == "dtrain.broadcast" {
			g.deliverBroadcast(b.Seq, b.Data)
		}
	}
}

func (g *Group) announce(ctx context.Context) error {
	b, err := json.Marshal(announcement{
		Type:  "dtrain.join",
		ID:    g.ID().String(),
		Addrs: addrStrings(g.ep.Addr()),
	})
	if err != nil {
		return fmt.Errorf("dtrain: encode announcement: %w", err)
	}
	if err := g.topic.Broadcast(ctx, b); err != nil {
		return fmt.Errorf("dtrain: broadcast announcement: %w", err)
	}
	return nil
}

func (g *Group) setMember(id key.EndpointID, addr netaddr.EndpointAddr, seen time.Time) {
	g.mu.Lock()
	defer g.mu.Unlock()
	old := g.members[id]
	if addr.IsEmpty() && !old.addr.IsEmpty() {
		addr = old.addr
	}
	g.members[id] = memberState{addr: addr, seen: seen}
	g.refreshLocked()
}

func (g *Group) removeMember(id key.EndpointID) {
	g.mu.Lock()
	defer g.mu.Unlock()
	delete(g.members, id)
	g.refreshLocked()
}

func (g *Group) refreshLocked() {
	next := make([]Member, 0, len(g.members))
	for id, state := range g.members {
		next = append(next, Member{ID: id, Addr: state.addr})
	}
	slices.SortFunc(next, func(a, b Member) int {
		return cmpString(a.ID.String(), b.ID.String())
	})
	for i := range next {
		next[i].Rank = i
	}
	if slices.EqualFunc(g.ranked, next, sameMember) {
		return
	}
	g.ranked = next
	g.emitLocked(Event{Kind: Membership, Members: slices.Clone(next)})
}

func (g *Group) emit(ev Event) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.emitLocked(ev)
}

func (g *Group) emitLocked(ev Event) {
	if g.closed {
		return
	}
	if ev.Members != nil {
		ev.Members = slices.Clone(ev.Members)
	}
	select {
	case g.events <- ev:
	default:
	}
}

func topicID(name string) gossip.TopicID {
	return gossip.TopicID(sha256.Sum256([]byte("dtrain:" + name)))
}

func cmpString(a, b string) int {
	if a < b {
		return -1
	}
	if a > b {
		return 1
	}
	return 0
}

func sameMember(a, b Member) bool {
	return a.ID == b.ID && a.Rank == b.Rank && slices.Equal(addrStrings(a.Addr), addrStrings(b.Addr))
}

// Op identifies an AllReduce operation.
type Op uint8

const (
	// Sum computes the elementwise sum.
	Sum Op = iota
	// Mean computes the elementwise mean.
	Mean
	// Max computes the elementwise maximum.
	Max
)

// AllReduce exchanges one vector with every peer and returns the reduced vector.
//
// AllReduce and [Group.Barrier] follow the SPMD collective model: every member
// must issue the same sequence of collectives in the same order. Collectives are
// correlated by a per-member sequence number, so a member that skips or reorders
// a collective desynchronizes the group and its peers block until the context
// deadline.
func (g *Group) AllReduce(ctx context.Context, values []float32, op Op) ([]float32, error) {
	if g == nil {
		return nil, errors.New("dtrain: nil group")
	}
	if g.h == nil {
		return nil, errors.New("dtrain: group has no stream handler")
	}
	members := g.Members()
	rank := g.Rank()
	if rank < 0 {
		return nil, errors.New("dtrain: local endpoint is not a member")
	}
	seq := g.seq.Add(1)
	local := slices.Clone(values)
	g.publishLocal(seq, local)
	defer g.clearLocal(seq)

	out := slices.Clone(values)
	for _, m := range members {
		if m.Rank == rank {
			continue
		}
		var peer []float32
		var err error
		if rank > m.Rank {
			peer, err = g.exchange(ctx, m, seq, op, values)
		} else {
			peer, err = g.waitInbound(ctx, seq)
		}
		if err != nil {
			return nil, err
		}
		if len(peer) != len(out) {
			return nil, fmt.Errorf("dtrain: peer vector length %d, want %d", len(peer), len(out))
		}
		reduceInto(out, peer, op)
	}
	if op == Mean && len(members) > 0 {
		scale := float32(len(members))
		for i := range out {
			out[i] /= scale
		}
	}
	return out, nil
}

// AllGather exchanges one vector with every peer and returns all vectors
// concatenated in rank order.
//
// Like [Group.AllReduce], AllGather is an SPMD collective: every member must
// call it in the same collective order. Each member must contribute a vector of
// the same length.
func (g *Group) AllGather(ctx context.Context, values []float32) ([]float32, error) {
	if g == nil {
		return nil, errors.New("dtrain: nil group")
	}
	if g.h == nil {
		return nil, errors.New("dtrain: group has no stream handler")
	}
	members := g.Members()
	rank := g.Rank()
	if rank < 0 {
		return nil, errors.New("dtrain: local endpoint is not a member")
	}
	seq := g.seq.Add(1)
	local := slices.Clone(values)
	g.publishLocal(seq, local)
	defer g.clearLocal(seq)

	parts := make([][]float32, len(members))
	have := make([]bool, len(members))
	parts[rank] = local
	have[rank] = true
	for _, m := range members {
		if m.Rank == rank {
			continue
		}
		var frame allReduceFrame
		var err error
		if rank > m.Rank {
			var peer []float32
			peer, err = g.exchange(ctx, m, seq, Sum, values)
			frame = allReduceFrame{From: m.ID.String(), Values: peer}
		} else {
			frame, err = g.waitInboundFrame(ctx, seq)
		}
		if err != nil {
			return nil, err
		}
		peerRank := rankOfMember(members, frame.From)
		if peerRank < 0 {
			return nil, fmt.Errorf("dtrain: allgather from unknown peer %q", frame.From)
		}
		if len(frame.Values) != len(values) {
			return nil, fmt.Errorf("dtrain: peer vector length %d, want %d", len(frame.Values), len(values))
		}
		parts[peerRank] = slices.Clone(frame.Values)
		have[peerRank] = true
	}
	out := make([]float32, 0, len(members)*len(values))
	for i, part := range parts {
		if !have[i] {
			return nil, fmt.Errorf("dtrain: missing allgather rank %d", i)
		}
		out = append(out, part...)
	}
	return out, nil
}

// ReduceScatter reduces one vector across all members and returns this rank's
// contiguous shard of the reduced vector.
//
// The vector length must be divisible by the current membership size. Like
// [Group.AllReduce], ReduceScatter is an SPMD collective.
func (g *Group) ReduceScatter(ctx context.Context, values []float32, op Op) ([]float32, error) {
	members := g.Members()
	rank := g.Rank()
	if rank < 0 {
		return nil, errors.New("dtrain: local endpoint is not a member")
	}
	if len(members) == 0 {
		return nil, errors.New("dtrain: empty group")
	}
	if len(values)%len(members) != 0 {
		return nil, fmt.Errorf("dtrain: vector length %d not divisible by group size %d", len(values), len(members))
	}
	reduced, err := g.AllReduce(ctx, values, op)
	if err != nil {
		return nil, err
	}
	shard := len(reduced) / len(members)
	start := rank * shard
	return slices.Clone(reduced[start : start+shard]), nil
}

func (g *Group) exchange(ctx context.Context, m Member, seq uint64, op Op, values []float32) ([]float32, error) {
	if m.Addr.IsEmpty() {
		return nil, fmt.Errorf("dtrain: no address for peer rank %d", m.Rank)
	}
	conn, err := g.ep.Connect(ctx, m.Addr, ALPN)
	if err != nil {
		return nil, fmt.Errorf("dtrain: connect peer rank %d: %w", m.Rank, err)
	}
	defer conn.Close()
	remote := conn.RemoteID()
	if remote.IsZero() {
		return nil, fmt.Errorf("dtrain: peer rank %d has no verified identity", m.Rank)
	}
	if !remote.Equal(m.ID) {
		return nil, fmt.Errorf("dtrain: peer rank %d identity mismatch: got %s want %s", m.Rank, remote, m.ID)
	}
	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		return nil, fmt.Errorf("dtrain: open allreduce stream: %w", err)
	}
	defer stream.Close()
	// Honor the caller's context deadline during stream I/O so a stalled or
	// crashed peer cannot wedge the collective forever.
	if deadline, ok := ctx.Deadline(); ok {
		stream.SetDeadline(deadline)
	}
	if err := writeAllReduce(stream, allReduceFrame{
		Group:  g.name,
		Seq:    seq,
		Op:     op,
		From:   g.ID().String(),
		Values: values,
	}); err != nil {
		return nil, err
	}
	frame, err := readAllReduce(stream)
	if err != nil {
		return nil, err
	}
	from, err := key.ParseEndpointID(frame.From)
	if err != nil {
		return nil, fmt.Errorf("dtrain: parse peer identity: %w", err)
	}
	if !from.Equal(remote) {
		return nil, fmt.Errorf("dtrain: peer rank %d response identity mismatch: got %s want %s", m.Rank, from, remote)
	}
	return frame.Values, nil
}

func (g *Group) publishLocal(seq uint64, values []float32) {
	g.mu.Lock()
	defer g.mu.Unlock()
	ch := make(chan []float32, 1)
	ch <- slices.Clone(values)
	g.pending[seq] = ch
	g.inbound[seq] = make(chan allReduceFrame, len(g.ranked))
}

func (g *Group) clearLocal(seq uint64) {
	g.mu.Lock()
	defer g.mu.Unlock()
	delete(g.pending, seq)
	delete(g.inbound, seq)
}

func (g *Group) waitLocal(ctx context.Context, seq uint64) ([]float32, error) {
	for {
		g.mu.Lock()
		ch := g.pending[seq]
		g.mu.Unlock()
		if ch != nil {
			select {
			case v := <-ch:
				ch <- slices.Clone(v)
				return v, nil
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(5 * time.Millisecond):
		}
	}
}

func (g *Group) deliverInbound(frame allReduceFrame) {
	g.mu.Lock()
	ch := g.inbound[frame.Seq]
	g.mu.Unlock()
	if ch == nil {
		return
	}
	select {
	case ch <- cloneAllReduceFrame(frame):
	default:
	}
}

func (g *Group) waitInbound(ctx context.Context, seq uint64) ([]float32, error) {
	frame, err := g.waitInboundFrame(ctx, seq)
	if err != nil {
		return nil, err
	}
	return frame.Values, nil
}

func (g *Group) waitInboundFrame(ctx context.Context, seq uint64) (allReduceFrame, error) {
	for {
		g.mu.Lock()
		ch := g.inbound[seq]
		g.mu.Unlock()
		if ch != nil {
			select {
			case f := <-ch:
				return f, nil
			case <-ctx.Done():
				return allReduceFrame{}, ctx.Err()
			}
		}
		select {
		case <-ctx.Done():
			return allReduceFrame{}, ctx.Err()
		case <-time.After(5 * time.Millisecond):
		}
	}
}

func rankOfMember(members []Member, id string) int {
	for _, m := range members {
		if m.ID.String() == id {
			return m.Rank
		}
	}
	return -1
}

func (g *Group) hasMember(id key.EndpointID) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	_, ok := g.members[id]
	return ok
}

func (h *Handler) register(name string, g *Group) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.groups[name] = g
}

func (h *Handler) unregister(name string, g *Group) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.groups[name] == g {
		delete(h.groups, name)
	}
}

// Accept serves dtrain streams on an iroh Router.
func (h *Handler) Accept(ctx context.Context, conn *iroh.Conn) error {
	for {
		stream, err := conn.AcceptStream(ctx)
		if err != nil {
			if ctx.Err() != nil || conn.Context().Err() != nil {
				return nil
			}
			return err
		}
		go h.serve(ctx, conn, stream)
	}
}

func (h *Handler) serve(ctx context.Context, conn *iroh.Conn, stream *iroh.Stream) {
	defer stream.Close()
	remote := conn.RemoteID()
	if remote.IsZero() {
		return
	}
	frame, err := readAllReduce(stream)
	if err != nil {
		return
	}
	from, err := key.ParseEndpointID(frame.From)
	if err != nil || !from.Equal(remote) {
		return
	}
	h.mu.Lock()
	group := h.groups[frame.Group]
	h.mu.Unlock()
	if group == nil {
		return
	}
	if !group.hasMember(remote) {
		return
	}
	group.deliverInbound(frame)
	values, err := group.waitLocal(ctx, frame.Seq)
	if err != nil {
		return
	}
	_ = writeAllReduce(stream, allReduceFrame{
		Group:  frame.Group,
		Seq:    frame.Seq,
		Op:     frame.Op,
		From:   group.ID().String(),
		Values: values,
	})
}

type allReduceFrame struct {
	Group  string
	Seq    uint64
	Op     Op
	From   string
	Values []float32
}

func cloneAllReduceFrame(f allReduceFrame) allReduceFrame {
	f.Values = slices.Clone(f.Values)
	return f
}

type allReduceHeader struct {
	Group string `json:"group"`
	Seq   uint64 `json:"seq"`
	Op    Op     `json:"op"`
	From  string `json:"from"`
	N     int    `json:"n"`
}

type broadcastMessage struct {
	Type string `json:"type"`
	Seq  uint64 `json:"seq"`
	Data []byte `json:"data"`
}

// Broadcast sends rank 0 data to every group member.
func (g *Group) Broadcast(ctx context.Context, rank0Data []byte) ([]byte, error) {
	if g == nil {
		return nil, errors.New("dtrain: nil group")
	}
	seq := g.bseq.Add(1)
	rank := g.Rank()
	if rank < 0 {
		return nil, errors.New("dtrain: local endpoint is not a member")
	}
	if rank == 0 {
		// Rank 0 has the data already and returns it directly below, so it does
		// not deliver to its own bcast channel — doing so left an entry in the
		// bcast map that only waitBroadcast (which rank 0 never calls) removes.
		data := slices.Clone(rank0Data)
		msg, err := json.Marshal(broadcastMessage{
			Type: "dtrain.broadcast",
			Seq:  seq,
			Data: data,
		})
		if err != nil {
			return nil, fmt.Errorf("dtrain: encode broadcast: %w", err)
		}
		if err := g.topic.Broadcast(ctx, msg); err != nil {
			return nil, fmt.Errorf("dtrain: broadcast: %w", err)
		}
		return data, nil
	}
	return g.waitBroadcast(ctx, seq)
}

// Barrier waits until every member reaches the same point. Like
// [Group.AllReduce], it is an SPMD collective: every member must call it in the
// same order relative to other collectives, or the group desynchronizes.
func (g *Group) Barrier(ctx context.Context) error {
	out, err := g.AllReduce(ctx, []float32{1}, Sum)
	if err != nil {
		return err
	}
	if len(out) != 1 || int(out[0]) != len(g.Members()) {
		return errors.New("dtrain: barrier did not include every member")
	}
	return nil
}

func (g *Group) deliverBroadcast(seq uint64, data []byte) {
	g.mu.Lock()
	ch := g.bcast[seq]
	if ch == nil {
		ch = make(chan []byte, 1)
		g.bcast[seq] = ch
	}
	g.mu.Unlock()
	select {
	case ch <- slices.Clone(data):
	default:
	}
}

func (g *Group) waitBroadcast(ctx context.Context, seq uint64) ([]byte, error) {
	for {
		g.mu.Lock()
		ch := g.bcast[seq]
		if ch == nil {
			ch = make(chan []byte, 1)
			g.bcast[seq] = ch
		}
		g.mu.Unlock()
		select {
		case data := <-ch:
			g.mu.Lock()
			delete(g.bcast, seq)
			g.mu.Unlock()
			return slices.Clone(data), nil
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
}

func writeAllReduce(w io.Writer, f allReduceFrame) error {
	h, err := json.Marshal(allReduceHeader{Group: f.Group, Seq: f.Seq, Op: f.Op, From: f.From, N: len(f.Values)})
	if err != nil {
		return fmt.Errorf("dtrain: encode allreduce header: %w", err)
	}
	if len(h) > math.MaxUint32 {
		return errors.New("dtrain: allreduce header too large")
	}
	if err := binary.Write(w, binary.BigEndian, uint32(len(h))); err != nil {
		return fmt.Errorf("dtrain: write allreduce header length: %w", err)
	}
	if _, err := w.Write(h); err != nil {
		return fmt.Errorf("dtrain: write allreduce header: %w", err)
	}
	if err := binary.Write(w, binary.BigEndian, uint64(len(f.Values))); err != nil {
		return fmt.Errorf("dtrain: write allreduce vector length: %w", err)
	}
	for _, v := range f.Values {
		if err := binary.Write(w, binary.BigEndian, math.Float32bits(v)); err != nil {
			return fmt.Errorf("dtrain: write allreduce value: %w", err)
		}
	}
	return nil
}

// Bounds on decoded frames. The ALPN is public, so a peer's declared sizes are
// untrusted; cap them before allocating to avoid an out-of-memory from a single
// oversized length field.
const (
	maxAllReduceHeader = 64 << 10 // JSON header is a few hundred bytes
	maxAllReduceValues = 64 << 20 // 64M float32 = 256 MiB
)

func readAllReduce(r io.Reader) (allReduceFrame, error) {
	var n uint32
	if err := binary.Read(r, binary.BigEndian, &n); err != nil {
		return allReduceFrame{}, fmt.Errorf("dtrain: read allreduce header length: %w", err)
	}
	if n > maxAllReduceHeader {
		return allReduceFrame{}, fmt.Errorf("dtrain: allreduce header too large: %d", n)
	}
	h := make([]byte, n)
	if _, err := io.ReadFull(r, h); err != nil {
		return allReduceFrame{}, fmt.Errorf("dtrain: read allreduce header: %w", err)
	}
	var header allReduceHeader
	if err := json.Unmarshal(h, &header); err != nil {
		return allReduceFrame{}, fmt.Errorf("dtrain: decode allreduce header: %w", err)
	}
	var vectorLen uint64
	if err := binary.Read(r, binary.BigEndian, &vectorLen); err != nil {
		return allReduceFrame{}, fmt.Errorf("dtrain: read allreduce vector length: %w", err)
	}
	if vectorLen != uint64(header.N) {
		return allReduceFrame{}, errors.New("dtrain: allreduce vector length mismatch")
	}
	if vectorLen > maxAllReduceValues {
		return allReduceFrame{}, fmt.Errorf("dtrain: allreduce vector too large: %d", vectorLen)
	}
	values := make([]float32, int(vectorLen))
	for i := range values {
		var bits uint32
		if err := binary.Read(r, binary.BigEndian, &bits); err != nil {
			return allReduceFrame{}, fmt.Errorf("dtrain: read allreduce value: %w", err)
		}
		values[i] = math.Float32frombits(bits)
	}
	return allReduceFrame{Group: header.Group, Seq: header.Seq, Op: header.Op, From: header.From, Values: values}, nil
}

func reduceInto(dst, src []float32, op Op) {
	for i, v := range src {
		switch op {
		case Max:
			if v > dst[i] {
				dst[i] = v
			}
		default:
			dst[i] += v
		}
	}
}

func addrStrings(addr netaddr.EndpointAddr) []string {
	addrs := addr.Addrs()
	out := make([]string, 0, len(addrs))
	for _, addr := range addrs {
		out = append(out, addr.String())
	}
	return out
}

func announcementAddr(id key.EndpointID, addrs []string) (netaddr.EndpointAddr, error) {
	addr := netaddr.NewEndpointAddr(id)
	for _, s := range addrs {
		a, err := netaddr.ParseTransportAddr(s)
		if err != nil {
			return netaddr.EndpointAddr{}, err
		}
		addr = addr.WithAddrs(a)
	}
	return addr, nil
}
