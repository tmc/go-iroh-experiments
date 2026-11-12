package irciroh

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	mrand "math/rand/v2"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/tmc/go-iroh/gossip"
	"github.com/tmc/go-iroh/iroh"
	"github.com/tmc/go-iroh/key"
	"github.com/tmc/go-iroh/netaddr"

	"github.com/tmc/go-iroh-experiments/mlsiroh"
	"github.com/tmc/mls"
)

// ErrNoChannel is returned for a channel this node has not joined.
var ErrNoChannel = errors.New("channel not joined")

// ErrNotReachable reports that the node knows no address a peer could
// dial, so it cannot mint a ticket. An endpoint bound to the unspecified
// address with relays disabled stays in this state until it discovers an
// external candidate.
var ErrNotReachable = errors.New("node has no address peers can reach")

// ErrFounded is returned by [Node.Join] and [Node.JoinTicket] for a
// plain join of a channel this node founded. The name of a sealed
// channel is also the name of a public one, and answering the request
// with the public channel would quietly move the caller from a group
// only the founder admits to a topic anyone who guesses the name can
// read. [Node.Found] is the way back in.
var ErrFounded = errors.New("this node founded that channel; use Found")

// ErrOtherChannel is returned by [Node.JoinTicket] for a ticket whose
// channel is not the one this node already has under that name. A
// channel's identity is its topic, which is made from its name and its
// secret together, so one name can stand for several channels - and a
// node can only be on one of them at a time, because IRC gives a client
// no way to tell two channels of one name apart. Answering with the one
// it happens to have would be the same quiet substitution [ErrFounded]
// refuses, arriving by a different road: the caller asked for a channel
// it holds a secret for and would be put on whatever a bare join
// claimed the name with earlier. [Channel.Part] is the way out.
var ErrOtherChannel = errors.New("this node is on another channel of that name")

// ErrClosed is returned for a join or a found on a node that has been
// closed.
var ErrClosed = errors.New("node closed")

// A Node is one chat participant: an iroh endpoint, a nick, and the
// channels it has joined. Create one with [NewNode] and close it with
// [Node.Close]. A Node is safe for concurrent use.
type Node struct {
	ep  *iroh.Endpoint
	g   *gossip.Gossip
	seq atomic.Uint64

	ctx    context.Context
	cancel context.CancelFunc

	mu       sync.Mutex
	nick     string
	channels map[string]*Channel
	closed   bool

	// founding serializes [Node.Found], which mints a channel's secret
	// and its group when it has none and must do each once.
	founding sync.Mutex

	private chan Event

	dmu    sync.Mutex
	dmSeen dmReplay

	// invites is what each endpoint may still spend on asking to join
	// a channel this node founded, and inviting bounds the invite
	// streams served at once. See [Node.mayAsk].
	imu      sync.Mutex
	invites  budgets
	inviting chan struct{}

	state *state
	rv    *rendezvous
	// find resolves a channel name into a member to bootstrap from.
	// It is a field rather than a call to [rendezvous.find] so that a
	// test can answer where the public name service would be asked:
	// the lookup is the whole of how a node that is cut off gets back,
	// and there was no way to exercise it. Nil means this node does
	// not look channels up, which is the default. See [WithRendezvous].
	find func(context.Context, string, []byte) (netaddr.EndpointAddr, error)
	// watch and merge are seek's two cadences, set once when the node
	// is made. They are fields rather than the constants themselves so
	// that a test can run the loop at a pace it can wait for, and
	// fields rather than package variables so that setting them races
	// with nothing.
	watch, merge time.Duration
	// history reports that this node keeps recent lines and asks for
	// them when it joins. See [WithHistory].
	history bool
	// quiet refuses a sender locally. See [WithQuiet].
	quiet func(key.EndpointID) bool
}

// An Option configures a [Node].
type Option func(*Node) error

// WithRendezvous lets the node find channels it has no ticket for, and
// be found on the ones it is in, through pkarr, the service iroh
// publishes endpoint addresses to. It is off unless asked for, because
// it publishes to a service outside this machine: a node that announces
// #go says, to anyone who thinks to look up that name, that it is
// there.
//
// A sealed channel announces under a key derived from its invite
// secret, so a node that has one is discoverable only to those already
// holding a ticket for it.
func WithRendezvous() Option {
	return func(n *Node) error {
		n.rv = &rendezvous{announced: make(map[string]*iroh.PkarrPublisher)}
		n.find = n.rv.find
		return nil
	}
}

// WithStateDir keeps the node's durable state in dir, creating it when
// something needs writing.
//
// Two things are kept: the invite secret of each channel this node
// founded, so that a restart re-founds the same channel rather than an
// unreachable new one, and the endpoints [Channel.Kick] turned away, so
// that a restart does not readmit them. They go together - a ban only
// means anything for a channel the banned endpoint can still find.
//
// The secrets are credentials; the package documentation's Durable
// state section says how they are written. Without this option a node
// writes nothing, and both the channel and its bans end with the
// process.
func WithStateDir(dir string) Option {
	return func(n *Node) error {
		st, err := openState(dir)
		if err != nil {
			return fmt.Errorf("state dir %s: %w", dir, err)
		}
		n.state = st
		return nil
	}
}

// WithQuiet refuses everything a sender says, on every channel this
// node is in, without telling it. It is the local half of a ban: the
// node decides for itself whose messages it will render, which is the
// only kind of decision a member of a serverless channel can make
// unilaterally. A part is still honoured, so a quieted member can
// still leave.
//
// This is where a founder's published ban list belongs, as advice
// rather than as enforcement: nothing can compel another node to honour
// a ban, so a node consults whatever lists its operator trusts and
// weighs them however it likes. Compare [Channel.Kick], which is the
// founder removing a member from a sealed channel's group and is
// enforcement, and the allow policy passed to [Node.Found], which is
// the founder deciding who gets in at all.
//
// A nil quiet, which is the default, refuses nobody.
func WithQuiet(quiet func(key.EndpointID) bool) Option {
	return func(n *Node) error {
		n.quiet = quiet
		return nil
	}
}

// NewNode returns a node that chats as nick over ep and g. Register
// [Node.Handler] under [ALPN] and the gossip handler under
// [gossip.ALPN] on the endpoint's router, or private messages will not
// arrive. The nick may be empty, and may not hold a space or a control
// character.
func NewNode(ep *iroh.Endpoint, g *gossip.Gossip, nick string, opts ...Option) (*Node, error) {
	if err := checkNick(nick); err != nil {
		return nil, fmt.Errorf("new node: %w", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	n := &Node{
		ep:       ep,
		g:        g,
		ctx:      ctx,
		cancel:   cancel,
		nick:     nick,
		channels: make(map[string]*Channel),
		private:  make(chan Event, 64),
		dmSeen:   make(dmReplay),
		invites:  make(budgets),
		inviting: make(chan struct{}, maxInviting),
		watch:    seekWatchInterval,
		merge:    seekMergeInterval,
	}
	// Seed the sequence counter from the wall clock so it does not
	// regress across restarts or rejoins.
	n.seq.Store(uint64(time.Now().UnixMilli()))
	for _, opt := range opts {
		if err := opt(n); err != nil {
			cancel()
			return nil, err
		}
	}
	return n, nil
}

// ID returns the node's endpoint identity.
func (n *Node) ID() key.EndpointID { return n.ep.ID() }

// Endpoint returns the node's iroh endpoint.
func (n *Node) Endpoint() *iroh.Endpoint { return n.ep }

// Nick returns the node's current nick.
func (n *Node) Nick() string {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.nick
}

// SetNick changes the node's nick and announces it on every joined
// channel. The announcement is asynchronous and best effort; peers that
// miss it learn the new nick from the next presence ping. A nick holding
// a space or a control character is refused, since every peer would
// drop what it was sent with.
func (n *Node) SetNick(nick string) error {
	if err := checkNick(nick); err != nil {
		return fmt.Errorf("set nick: %w", err)
	}
	n.mu.Lock()
	n.nick = nick
	chans := make([]*Channel, 0, len(n.channels))
	for _, c := range n.channels {
		chans = append(chans, c)
	}
	n.mu.Unlock()
	for _, c := range chans {
		c.mu.Lock()
		if m := c.members[n.ID()]; m != nil {
			m.nick = nick
		}
		c.mu.Unlock()
		go func(c *Channel) {
			ctx, cancel := context.WithTimeout(n.ctx, presenceSweep)
			defer cancel()
			_, _ = c.broadcast(ctx, kindNick, nick)
		}(c)
	}
	return nil
}

// Addr returns an address at which peers can reach this node, which may
// carry no addresses at all.
//
// The endpoint reports what it knows it is reachable at: direct
// candidates it has discovered and, when relays are enabled, its home
// relay. It deliberately leaves out the address it is bound to, because
// unless the caller chose one that is the unspecified address - every
// interface on this host - and a peer that dials it reaches its own
// loopback instead. Putting it back would make a [Ticket] that looks
// complete and cannot be dialed, which is worse than an empty one: the
// join fails at a timeout rather than at the ticket.
//
// A node bound to the unspecified address with relays disabled has
// nothing to advertise until it discovers an external candidate. That is
// a reachability problem, not something this function can paper over.
func (n *Node) Addr() netaddr.EndpointAddr {
	return n.ep.Addr()
}

// PeerAddr returns an address for a peer: the paths the endpoint already
// knows, or the bare id when it knows none.
//
// The bare id is not a failure to report. Most members of a channel are
// heard only through gossip, so the endpoint has never had a path of its
// own to them, and an address holding nothing but an id is what the
// endpoint's address lookup takes: it resolves the id through the same
// pkarr records a ticket would have carried. Returning nothing instead
// refused to dial a peer that was sitting in the channel, which is how a
// message to a member listed in NAMES came back as no route to that
// peer. A peer that really cannot be reached is found out by dialing it,
// and says so with a dial error naming what failed.
func (n *Node) PeerAddr(id key.EndpointID) netaddr.EndpointAddr {
	info, ok := n.ep.RemoteInfo(id)
	if !ok {
		return netaddr.NewEndpointAddr(id)
	}
	addrs := make([]netaddr.TransportAddr, 0, len(info.Addrs))
	for _, a := range info.Addrs {
		addrs = append(addrs, a.Addr)
	}
	return netaddr.NewEndpointAddr(id, addrs...)
}

// keyPackageLifetime is how long a key package minted for a sealed
// channel's join stays valid. It is short because it is used once,
// within the exchange that mints it.
const keyPackageLifetime = time.Hour

// Found creates a sealed channel with this node as its founder, and
// returns the channel and the ticket that admits others to it.
//
// A sealed channel is an MLS group: its gossip payloads are readable
// only by its members, membership is the group's roster rather than
// whoever is listening to the topic, and a member who leaves cannot read
// what is said afterwards. The founder is the only member that commits,
// which is how a serverless channel gets the total order on commits that
// RFC 9420 requires; the cost is that nobody can join or be removed
// while the founder is away. See the comment on sealed for the rest.
//
// allow decides which endpoints may join. A nil allow admits anyone
// presenting the ticket's secret, which is IRC's invite model; a
// non-nil one is consulted as well, and is the reason the ticket is not
// the whole of the access decision. The joiner's endpoint is proved by
// the transport, so the policy is written in endpoint ids rather than in
// names or tokens.
//
// Register [Node.InviteHandler] under [InviteALPN] before calling Found,
// or nobody can join.
func (n *Node) Found(ctx context.Context, ch string, allow func(key.EndpointID) bool) (*Channel, Ticket, error) {
	name, err := checkChannel(ch)
	if err != nil {
		return nil, Ticket{}, fmt.Errorf("found: %w", err)
	}
	n.founding.Lock()
	defer n.founding.Unlock()
	// A founder that kept state re-founds the channel it had: the same
	// secret is the same topic, so tickets already handed out still
	// work and an endpoint that was kicked is still kicked. The group
	// itself does not come back - epoch secrets are never written down
	// - so every member rejoins, through the invite exchange where the
	// ban list is consulted.
	secret := n.state.secret(name)
	if secret == nil {
		secret = make([]byte, secretSize)
		if _, err := rand.Read(secret); err != nil {
			return nil, Ticket{}, fmt.Errorf("found %s: %w", name, err)
		}
		if err := n.state.setSecret(name, secret); err != nil {
			return nil, Ticket{}, fmt.Errorf("found %s: %w", name, err)
		}
	}
	ticket := Ticket{Channel: name, Secret: secret, Founder: n.ID(), Peers: []netaddr.EndpointAddr{ticketAddr(n.Addr())}}

	// Founding a channel this node is already on returns it as it
	// stands. A fresh group would leave the members of the live one
	// talking to a founder that no longer holds their epoch, and a
	// client that reconnects and re-joins every channel it had asks
	// for exactly that.
	if c, ok := n.Channel(name); ok {
		if c.seal == nil || !c.seal.isFounder() {
			return nil, Ticket{}, fmt.Errorf("found %s: channel already joined", name)
		}
		return c, ticket, nil
	}

	client, err := mlsiroh.NewClient(n.secret(), keyPackageLifetime)
	if err != nil {
		return nil, Ticket{}, fmt.Errorf("found %s: %w", name, err)
	}
	// The group id is the folded channel name, so a member can tell
	// from a message header which channel it belongs to without being
	// able to read it.
	g, err := client.NewGroup([]byte(name), nil)
	if err != nil {
		return nil, Ticket{}, fmt.Errorf("found %s: %w", name, err)
	}
	c, err := n.subscribe(ctx, Ticket{Channel: name, Secret: secret, Founder: n.ID()})
	if err != nil {
		return nil, Ticket{}, err
	}
	if c.seal == nil {
		return nil, Ticket{}, fmt.Errorf("found %s: channel already joined", name)
	}
	c.seal.found(client, g, allow)
	if err := n.start(ctx, c); err != nil {
		return nil, Ticket{}, err
	}
	return c, ticket, nil
}

// Join subscribes to a public channel. bootstrap may be empty when this
// node already has neighbors on the topic or expects to be found by them.
// With bootstrap peers, Join waits a bounded time for the channel's
// gossip topic to have a neighbor, and joins anyway if none answers.
func (n *Node) Join(ctx context.Context, ch string, bootstrap []netaddr.EndpointAddr) (*Channel, error) {
	return n.JoinTicket(ctx, Ticket{Channel: ch, Peers: bootstrap})
}

// JoinTicket subscribes to the channel a ticket names, using its secret and
// its peers. It is how a node joins a channel whose topic is derived from a
// secret. As with [Node.Join], a ticket that carries peers makes the join
// wait a bounded time for the swarm.
func (n *Node) JoinTicket(ctx context.Context, t Ticket) (*Channel, error) {
	if t.Sealed() && t.Founder == n.ID() {
		return nil, fmt.Errorf("join %s: this node is the founder; use Found", t.Channel)
	}
	// A public channel's topic comes from its name alone, so joining
	// one by name is how a node ends up somewhere anybody who guesses
	// the name can read. That is the bargain on a channel this node
	// never sealed; it is not one to make silently on a channel it
	// founded. A client reconnecting sends a bare JOIN for every
	// channel it remembers, which without this would answer a sealed
	// channel with a public one wearing the same name.
	if !t.Sealed() {
		if name, err := checkChannel(t.Channel); err == nil && n.state.secret(name) != nil {
			return nil, fmt.Errorf("join %s: %w", name, ErrFounded)
		}
	}
	c, err := n.subscribe(ctx, t)
	if err != nil {
		return nil, err
	}
	if c.seal != nil {
		if err := n.seat(ctx, c, t); err != nil {
			return nil, err
		}
	}
	if err := n.start(ctx, c); err != nil {
		return nil, err
	}
	// The join is finished either way: asking what was said before it
	// dials a peer, and a member that cannot be reached, or will not
	// answer, is not a reason to fail a join that has already
	// succeeded. See history.go.
	if n.history && c.seal == nil {
		go c.recallOnJoin(t.Peers)
	}
	return c, nil
}

// seat asks the founder for the group state of a sealed channel this node
// has subscribed to. The topic subscription is only half a sealed join:
// the group state comes from the founder, who commits the Add. Joins of
// one channel at once ask once, and the rest find it seated; each ask
// costs the founder a commit and the joiner a place in its rate limit.
//
// A channel already seated returns at once, without waiting on a rejoin
// in progress: that is a reconnecting client re-joining what it has.
func (n *Node) seat(ctx context.Context, c *Channel, t Ticket) error {
	if c.seal.seated() {
		return nil
	}
	c.resyncing.Lock()
	defer c.resyncing.Unlock()
	select {
	case <-c.quit:
		return fmt.Errorf("join %s: a join of the channel running at the same time failed", c.name)
	default:
	}
	if c.seal.seated() {
		return nil
	}
	client, g, err := n.ask(ctx, t, t.Peers)
	if err != nil {
		n.forget(c)
		c.shutdown()
		return err
	}
	c.seal.adopt(client, g)
	return nil
}

// subscribe joins the ticket's gossip topic and registers the channel,
// leaving it stopped: no goroutines and no join announcement. It returns
// an already-joined channel unchanged.
func (n *Node) subscribe(ctx context.Context, t Ticket) (*Channel, error) {
	name, err := checkChannel(t.Channel)
	if err != nil {
		return nil, fmt.Errorf("join: %w", err)
	}
	n.mu.Lock()
	if n.closed {
		n.mu.Unlock()
		return nil, fmt.Errorf("join %s: %w", name, ErrClosed)
	}
	if c, ok := n.channels[name]; ok {
		n.mu.Unlock()
		// The name matched; the channel is the topic. A ticket that
		// names a different one is refused rather than answered with
		// this one, so that a caller holding a secret is never
		// quietly put on the channel a bare join claimed the name
		// with first.
		//
		// A ticket with no secret and no founder names no channel in
		// particular, only a name, and is answered with whatever this
		// node has under it. That is the reconnecting client, which
		// re-joins every channel it had with a bare JOIN because IRC
		// gives it nowhere to keep a ticket. Refusing it would be
		// refusing a caller the channel it is already on.
		if t.names() && c.topic.ID() != t.topic() {
			return nil, fmt.Errorf("join %s: %w", name, ErrOtherChannel)
		}
		// The channel is the one asked for, but the ticket is not
		// therefore spent: what it carries is a hint about where the
		// channel is, and a node already on a topic can still have
		// nobody on it. That is a fleet that started together and
		// found each other absent, and it is precisely who gets
		// handed a ticket by somebody watching them sit alone. On a
		// public channel the peers are the whole of the ticket, since
		// the topic comes from the name.
		//
		// Best effort, like [Channel.seek]'s, which is the same event
		// arriving by the other route: a hint that has gone stale is
		// no reason to fail a join that is otherwise fine.
		if peers := withoutSelf(t.Peers, n.ID()); len(peers) > 0 {
			_ = c.topic.JoinPeers(ctx, peers)
		}
		return c, nil
	}
	nick := n.nick
	n.mu.Unlock()

	// A join with no peer of its own asks the channel where it is. A
	// ticket that names one is left alone: it was given to this node
	// for this channel, and it is the more direct answer.
	//
	// This node is never its own bootstrap peer, whether the address
	// came from a ticket or from the rendezvous record it published on
	// an earlier run. Waiting for the swarm means waiting for a
	// neighbor, and a node cannot be its own neighbor: it would wait
	// for itself to arrive, forever. The founder re-founding a channel
	// after a restart is exactly that case, since the record it finds
	// is the one it wrote.
	peers := withoutSelf(t.Peers, n.ID())
	if len(peers) == 0 && n.find != nil {
		find, cancel := context.WithTimeout(ctx, findTimeout)
		addr, err := n.find(find, name, t.Secret)
		cancel()
		if err == nil && addr.ID != n.ID() {
			peers = []netaddr.EndpointAddr{addr}
		}
	}

	topic, err := n.g.Subscribe(ctx, t.topic(), peers)
	if err != nil {
		return nil, fmt.Errorf("join %s: %w", name, err)
	}
	// With bootstrap peers, wait for the swarm: a broadcast made before
	// the topic has a neighbor goes nowhere. The wait is bounded and
	// running out of it is not a failure. A bootstrap address on a
	// serverless network is a hint, and hints go stale - a rendezvous
	// record outlives the run that published it - so refusing the join
	// because nobody answered would keep a member off a channel that
	// is working. Subscribed is the durable part; the topic meets
	// whoever arrives later.
	if len(peers) > 0 {
		join, cancel := context.WithTimeout(ctx, joinTimeout)
		err := topic.Joined(join)
		cancel()
		if err != nil && ctx.Err() != nil {
			_ = topic.Close()
			return nil, fmt.Errorf("join %s: %w", name, ctx.Err())
		}
	}
	c := &Channel{
		node:    n,
		name:    name,
		secret:  t.Secret,
		topic:   topic,
		quit:    make(chan struct{}),
		events:  make(chan Event, 64),
		members: make(map[key.EndpointID]*member),
		lastSeq: make(seqSet),
		spent:   make(budgets),
	}
	if t.Sealed() {
		c.seal = &sealed{
			ch:      c,
			sk:      n.secret(),
			founder: t.Founder,
			invite:  t.Secret,
			roster:  make(map[key.EndpointID]mls.LeafIndex),
			state:   n.state,
		}
		// A ban recorded before the last restart is still a ban.
		for _, id := range n.state.bans(name) {
			c.seal.ban(id)
		}
	}
	now := time.Now()
	c.touch(n.ID(), nick, now)

	n.mu.Lock()
	if n.closed {
		n.mu.Unlock()
		_ = topic.Close()
		return nil, fmt.Errorf("join %s: %w", name, ErrClosed)
	}
	if got, ok := n.channels[name]; ok {
		n.mu.Unlock()
		_ = topic.Close()
		return got, nil
	}
	n.channels[name] = c
	n.mu.Unlock()
	return c, nil
}

// start runs a registered channel's goroutines and announces this node
// on it. A sealed channel must already hold its group state.
func (n *Node) start(ctx context.Context, c *Channel) error {
	if !c.started.CompareAndSwap(false, true) {
		return nil
	}
	go c.run()
	go c.keepalive()
	if _, err := c.broadcast(ctx, kindJoin, ""); err != nil {
		n.forget(c)
		c.shutdown()
		return fmt.Errorf("join %s: %w", c.name, err)
	}
	// Announce only once this node is in the swarm, so a joiner that
	// resolves the record reaches a member rather than a node that is
	// still arriving. A node with no address to announce stays quiet;
	// it can take part in the channel, it just cannot be the way in.
	if n.rv != nil {
		if addr := n.Addr(); len(addr.Addrs()) > 0 {
			_ = n.rv.announce(c.name, c.secret, n.ID(), addr)
		}
	}
	// Being announced and being able to look others up are separate:
	// a node with no address to announce still has to find the
	// channel, and seek does nothing without somewhere to ask.
	if n.find != nil {
		go c.seek()
	}
	return nil
}

// seek looks for a way into a channel that has no neighbors, for as
// long as the channel is open.
//
// A join by name resolves the rendezvous record once, before the topic
// is subscribed, and a member announces itself only once it is in the
// swarm: a set of nodes that all arrive before any of them has
// announced therefore finds nothing, and without this would stay apart
// for good rather than for a moment. That is not a corner case - it is
// what a fleet restarted together does.
//
// Looking again is the same argument the join already makes for a
// stale bootstrap address, which is that a hint on a serverless network
// is a hint: an absent one is no more a reason to give up than a wrong
// one.
//
// Having a neighbor is a reason to look less often, not a reason to
// stop. The swarm is the way in only while this node is in it, and it
// fails in two ways. Gossip drops a neighbor when its peer goes away,
// so a node whose last neighbor restarts is back where it began. And a
// node can hold neighbors that are all each other: a pocket is locally
// indistinguishable from the room, since every node in it has peers,
// exchanges presence and reports itself healthy, while the rest of the
// channel is somewhere else. Neither heals if looking stops.
//
// So seek keeps looking either way, eagerly while there is no way in
// and slowly once there is. The slow lookup is what merges pockets,
// and it works because the rendezvous record holds one member at a
// time and the writers race for it: a node that looks once draws its
// own pocket as often as not, and a node that keeps looking draws the
// whole channel eventually. What makes the record a poor directory is
// exactly what makes it mix.
//
// What counts as a way in is the roster, not the neighbor set. A
// neighbor is one this node attached to, and attaching does not require
// being able to read it: two nodes that sign in different domains
// become neighbors and exchange nothing, so a node that judged by
// neighbors would settle into its slow cadence on a peer it cannot
// understand and call that repair.
func (c *Channel) seek() {
	for {
		wait := seekInterval
		for !c.reached() {
			if !c.pause(spread(wait)) {
				return
			}
			if wait *= 2; wait > seekMaxInterval {
				wait = seekMaxInterval
			}
			if !c.reach() {
				return
			}
		}
		// In the swarm, as far as this node can tell. Watch often,
		// because losing the last neighbor should be noticed
		// promptly; look for a stranger rarely, because that is a
		// lookup with nothing wrong to justify it.
		for next := time.Now().Add(spread(c.node.merge)); c.reached(); {
			if !c.pause(c.node.watch) {
				return
			}
			if time.Now().Before(next) {
				continue
			}
			next = time.Now().Add(spread(c.node.merge))
			if !c.reach() {
				return
			}
		}
	}
}

// reached reports whether the channel has a member other than this node
// that it has heard from, could verify, and heard from recently. A
// member is written down only by [Channel.apply], for a sender already
// authenticated, or by this node writing itself, so a member that is
// not this node is a peer whose message verified. That is the signal
// seek has that a neighbor is a way in rather than an attachment.
//
// It reads c.members rather than calling [Channel.Members], which on a
// sealed channel answers from the group roster instead: a founder that
// invited somebody and then lost every neighbor has a group of two and
// has reached nobody. The seen cutoff is what makes this a question
// about now rather than about who was once admitted.
//
// The narrow case it gets wrong: a verified presence can still be
// dropped by the presence budget, so a peer flooding presence can be
// found and not counted. A newcomer is given more burst than one ping
// spends, so this does not reach the ordinary join.
func (c *Channel) reached() bool {
	self := c.node.ID()
	cutoff := time.Now().Add(-presenceTimeout)
	c.mu.Lock()
	defer c.mu.Unlock()
	for id, m := range c.members {
		if id != self && m.seen.After(cutoff) {
			return true
		}
	}
	return false
}

// reach asks the rendezvous record for a member of the channel and
// joins it, and reports whether the channel is still open. A lookup
// that finds nobody, finds this node, or fails is not an error: the
// record names whoever wrote it last, and seek will ask again.
func (c *Channel) reach() bool {
	if c.node.find == nil {
		return true
	}
	find, cancel := context.WithTimeout(c.node.ctx, findTimeout)
	addr, err := c.node.find(find, c.name, c.secret)
	cancel()
	if c.node.ctx.Err() != nil {
		return false
	}
	if err != nil || addr.ID == c.node.ID() {
		return true
	}
	_ = c.topic.JoinPeers(c.node.ctx, []netaddr.EndpointAddr{addr})
	return true
}

// spread scatters d over the interval from half to one and a half
// times it, so that a wait of a nominal length does not recur on a
// fixed cadence.
//
// The slow lookup reads a rendezvous record that every member of the
// channel rewrites on its own fixed timer, and a record that holds one
// member at a time turns that into a rotation whose period is the
// timer. A lookup whose own period is an integer multiple of it
// samples one phase of the rotation forever and draws the same member
// every time, which is a node asking an hour of questions it already
// knows the answer to, and it looks like nothing at all from inside:
// the answer verifies and names a live member. Dividing the period is
// harmless - that is full coverage - so the hazard is a short list of
// multiples rather than a bad choice of constant.
//
// It is a short list this package cannot check. The interval being
// locked against is a dependency's publishing default, which irciroh
// neither sets nor reads, so any constant chosen to avoid it would
// come quietly undone when that default moved. A spread wait avoids
// the whole family without naming a member of it.
func spread(d time.Duration) time.Duration {
	if d <= 0 {
		return d
	}
	return d/2 + time.Duration(mrand.Int64N(int64(d)))
}

// pause waits for d, and reports whether the channel is still open.
func (c *Channel) pause(d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-c.quit:
		return false
	case <-c.node.ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

// withoutSelf returns the addresses in peers that are not self.
func withoutSelf(peers []netaddr.EndpointAddr, self key.EndpointID) []netaddr.EndpointAddr {
	out := make([]netaddr.EndpointAddr, 0, len(peers))
	for _, p := range peers {
		if p.ID != self {
			out = append(out, p)
		}
	}
	return out
}

// Channel returns a joined channel by name.
func (n *Node) Channel(name string) (*Channel, bool) {
	n.mu.Lock()
	defer n.mu.Unlock()
	c, ok := n.channels[Fold(name)]
	return c, ok
}

// Channels returns every channel this node has joined, ordered by name.
func (n *Node) Channels() []*Channel {
	n.mu.Lock()
	defer n.mu.Unlock()
	out := make([]*Channel, 0, len(n.channels))
	for _, c := range n.channels {
		out = append(out, c)
	}
	slices.SortFunc(out, func(a, b *Channel) int { return strings.Compare(a.name, b.name) })
	return out
}

// Ticket returns a ticket for a joined channel: its name, its secret, and
// this node's address, and for a sealed channel the founder's address
// when this node knows one.
func (n *Node) Ticket(ch string) (Ticket, error) {
	c, ok := n.Channel(ch)
	if !ok {
		return Ticket{}, fmt.Errorf("ticket for %s: %w", ch, ErrNoChannel)
	}
	addr := ticketAddr(n.Addr())
	if len(addr.Addrs()) == 0 {
		// A ticket whose peer cannot be dialed is worse than no ticket:
		// its holder waits for a join that nothing will answer. Say so
		// here, where the caller can still do something about it.
		return Ticket{}, fmt.Errorf("ticket for %s: %w", ch, ErrNotReachable)
	}
	t := Ticket{
		Channel: c.name,
		Secret:  c.secret,
		Peers:   []netaddr.EndpointAddr{addr},
	}
	if c.seal != nil {
		t.Founder = c.seal.founder
		// This node is a way into the swarm, but only the founder
		// admits, so a ticket minted by any other member has to say
		// where the founder is too. A founder this node has no path
		// to is left out; the joiner still looks it up by id.
		if t.Founder != n.ID() {
			if fa := ticketAddr(n.PeerAddr(t.Founder)); len(fa.Addrs()) > 0 {
				t.Peers = append(t.Peers, fa)
			}
		}
	}
	return t, nil
}

// ticketAddr reduces an address to what a ticket should carry.
//
// An endpoint advertises the IP candidates it was discovered at as well
// as its home relay, and a peer that dials the relay negotiates a direct
// path from there. So the addresses buy a ticket nothing: the direct
// path is reached either way. What they cost is that a ticket names the
// address its minter was seen at, to everyone it is ever forwarded to,
// long after the join it was written for. A ticket travels further than
// a connection does, so it carries the relay alone when there is one.
//
// With no relay the IP candidates are the only way to be reached, and
// leaving them out would make the ticket useless rather than private.
func ticketAddr(addr netaddr.EndpointAddr) netaddr.EndpointAddr {
	relays := addr.RelayURLs()
	if len(relays) == 0 {
		return addr
	}
	out := netaddr.EndpointAddr{ID: addr.ID}
	for _, u := range relays {
		out = out.WithRelayURL(u)
	}
	return out
}

// Close parts every channel and stops the node. It does not shut down the
// endpoint or the gossip instance, which the caller owns.
func (n *Node) Close() error {
	n.mu.Lock()
	n.closed = true
	chans := make([]*Channel, 0, len(n.channels))
	for _, c := range n.channels {
		chans = append(chans, c)
	}
	clear(n.channels)
	n.mu.Unlock()

	if n.rv != nil {
		n.rv.close()
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	var errs []error
	for _, c := range chans {
		if _, err := c.broadcast(ctx, kindPart, ""); err != nil {
			errs = append(errs, err)
		}
		c.shutdown()
	}
	n.cancel()
	return errors.Join(errs...)
}

// forget removes a channel from the node's table.
func (n *Node) forget(c *Channel) {
	n.mu.Lock()
	registered := n.channels[c.name] == c
	if registered {
		delete(n.channels, c.name)
	}
	n.mu.Unlock()
	// A channel parted and rejoined under the same name is a new
	// object, and an old one parted again must not take it along.
	if registered && n.rv != nil {
		// A node that has left is no longer a way in.
		n.rv.stop(c.name)
	}
}

// secret returns the endpoint's signing key.
func (n *Node) secret() key.SecretKey { return n.ep.SecretKey() }

// nextSeq returns the next envelope sequence number.
func (n *Node) nextSeq() uint64 { return n.seq.Add(1) }
