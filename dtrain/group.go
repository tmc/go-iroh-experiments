package dtrain

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"sync"
	"time"

	"github.com/tmc/go-iroh/gossip"
	"github.com/tmc/go-iroh/iroh"
	"github.com/tmc/go-iroh/key"
	"github.com/tmc/go-iroh/netaddr"
)

const announceEvery = 200 * time.Millisecond

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
}

// Group is a ranked training group backed by an iroh-gossip topic.
type Group struct {
	ep    *iroh.Endpoint
	topic *gossip.Topic

	ctx    context.Context
	cancel context.CancelFunc
	done   chan struct{}

	mu      sync.Mutex
	members map[key.EndpointID]time.Time
	ranked  []Member
	events  chan Event
	closed  bool
}

type announcement struct {
	Type string `json:"type"`
	ID   string `json:"id"`
}

// JoinGroup joins name using g and returns a ranked group handle.
func JoinGroup(ctx context.Context, ep *iroh.Endpoint, g *gossip.Gossip, name string, bootstrap []netaddr.EndpointAddr) (*Group, error) {
	if ep == nil {
		return nil, errors.New("dtrain: nil endpoint")
	}
	if g == nil {
		return nil, errors.New("dtrain: nil gossip")
	}
	if name == "" {
		return nil, errors.New("dtrain: empty group name")
	}
	topic, err := g.Subscribe(ctx, topicID(name), bootstrap)
	if err != nil {
		return nil, fmt.Errorf("dtrain: subscribe group: %w", err)
	}
	runCtx, cancel := context.WithCancel(context.Background())
	group := &Group{
		ep:      ep,
		topic:   topic,
		ctx:     runCtx,
		cancel:  cancel,
		done:    make(chan struct{}),
		members: make(map[key.EndpointID]time.Time),
		events:  make(chan Event, 128),
	}
	group.setMember(ep.ID(), time.Now())
	if err := group.announce(ctx); err != nil {
		_ = topic.Close()
		cancel()
		return nil, err
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
		g.setMember(ev.Peer, time.Now())
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
		g.setMember(id, time.Now())
	}
}

func (g *Group) announce(ctx context.Context) error {
	b, err := json.Marshal(announcement{Type: "dtrain.join", ID: g.ID().String()})
	if err != nil {
		return fmt.Errorf("dtrain: encode announcement: %w", err)
	}
	if err := g.topic.Broadcast(ctx, b); err != nil {
		return fmt.Errorf("dtrain: broadcast announcement: %w", err)
	}
	return nil
}

func (g *Group) setMember(id key.EndpointID, seen time.Time) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.members[id] = seen
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
	for id := range g.members {
		next = append(next, Member{ID: id})
	}
	slices.SortFunc(next, func(a, b Member) int {
		return cmpString(a.ID.String(), b.ID.String())
	})
	for i := range next {
		next[i].Rank = i
	}
	if slices.EqualFunc(g.ranked, next, func(a, b Member) bool {
		return a.ID == b.ID && a.Rank == b.Rank
	}) {
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
