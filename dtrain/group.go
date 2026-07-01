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
	pending map[uint64]chan []float32
	inbound map[uint64]chan []float32
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
		inbound: make(map[uint64]chan []float32),
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
	for {
		for ev, err := range g.topic.Events() {
			if err != nil {
				g.emit(Event{Kind: Leave})
				return
			}
			g.handle(ev)
			break
		}
		select {
		case <-g.ctx.Done():
			return
		default:
		}
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
		if err := json.Unmarshal(ev.Content, &a); err != nil || a.Type != "dtrain.join" {
			return
		}
		id, err := key.ParseEndpointID(a.ID)
		if err != nil {
			return
		}
		addr, err := announcementAddr(id, a.Addrs)
		if err != nil {
			return
		}
		g.setMember(id, addr, time.Now())
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

func (g *Group) exchange(ctx context.Context, m Member, seq uint64, op Op, values []float32) ([]float32, error) {
	if m.Addr.IsEmpty() {
		return nil, fmt.Errorf("dtrain: no address for peer rank %d", m.Rank)
	}
	conn, err := g.ep.Connect(ctx, m.Addr, ALPN)
	if err != nil {
		return nil, fmt.Errorf("dtrain: connect peer rank %d: %w", m.Rank, err)
	}
	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		return nil, fmt.Errorf("dtrain: open allreduce stream: %w", err)
	}
	defer stream.Close()
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
	return frame.Values, nil
}

func (g *Group) publishLocal(seq uint64, values []float32) {
	g.mu.Lock()
	defer g.mu.Unlock()
	ch := make(chan []float32, 1)
	ch <- slices.Clone(values)
	g.pending[seq] = ch
	g.inbound[seq] = make(chan []float32, len(g.ranked))
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

func (g *Group) deliverInbound(seq uint64, values []float32) {
	g.mu.Lock()
	ch := g.inbound[seq]
	g.mu.Unlock()
	if ch == nil {
		return
	}
	select {
	case ch <- slices.Clone(values):
	default:
	}
}

func (g *Group) waitInbound(ctx context.Context, seq uint64) ([]float32, error) {
	for {
		g.mu.Lock()
		ch := g.inbound[seq]
		g.mu.Unlock()
		if ch != nil {
			select {
			case v := <-ch:
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
		go h.serve(ctx, stream)
	}
}

func (h *Handler) serve(ctx context.Context, stream *iroh.Stream) {
	defer stream.Close()
	frame, err := readAllReduce(stream)
	if err != nil {
		return
	}
	h.mu.Lock()
	group := h.groups[frame.Group]
	h.mu.Unlock()
	if group == nil {
		return
	}
	group.deliverInbound(frame.Seq, frame.Values)
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

type allReduceHeader struct {
	Group string `json:"group"`
	Seq   uint64 `json:"seq"`
	Op    Op     `json:"op"`
	From  string `json:"from"`
	N     int    `json:"n"`
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

func readAllReduce(r io.Reader) (allReduceFrame, error) {
	var n uint32
	if err := binary.Read(r, binary.BigEndian, &n); err != nil {
		return allReduceFrame{}, fmt.Errorf("dtrain: read allreduce header length: %w", err)
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
	if vectorLen > uint64(math.MaxInt) {
		return allReduceFrame{}, errors.New("dtrain: allreduce vector too large")
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
