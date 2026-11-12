package irciroh

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/tmc/go-iroh/dns"
	"github.com/tmc/go-iroh/iroh"
	"github.com/tmc/go-iroh/key"
	"github.com/tmc/go-iroh/netaddr"
	"lukechampine.com/blake3"
)

// A rendezvous is how a node finds a channel it has no ticket for.
//
// Reaching a channel takes a peer already in its swarm, and nothing in
// gossip says who that is. The name does: a channel derives a keypair
// that everyone who can address the channel can derive too, and members
// announce themselves under it through the endpoint-discovery service
// the endpoint already uses to publish its own address. A joiner
// resolves that key and gets a member to bootstrap from.
//
// What "everyone who can address the channel" means is the point of the
// secret in the derivation. A public channel derives from its name
// alone, which is what makes /join #go work with nothing else; a sealed
// channel derives from its invite secret, so only a ticket holder can
// resolve it - the same boundary [SealedTopicID] draws, for the same
// reason. Announcing a sealed channel under its name would publish the
// roster the sealed topic exists to hide.
//
// The record is a hint and nothing more. Anyone who can derive the key
// can write it, so a joiner may be pointed at an endpoint that is dead,
// or at one that never was a member. Neither gains anything: the swarm
// admits whoever reaches it in a public channel, and the founder's
// invite exchange admits a sealed one. A bad record costs a joiner a
// dial, not a seat.
type rendezvous struct {
	lookup *iroh.AddressLookupServices

	mu        sync.Mutex
	announced map[string]*iroh.PkarrPublisher // by channel name
}

// ErrNoRendezvous reports that no member of a channel could be found
// through its rendezvous record.
var ErrNoRendezvous = errors.New("no member announced on the channel")

// rendezvousKey derives the keypair a channel announces itself under.
// The secret is empty for a public channel, so its key follows from the
// name alone.
func rendezvousKey(channel string, secret []byte) key.SecretKey {
	b := make([]byte, 0, 32+len(channel)+len(secret))
	b = append(b, "irciroh/rendezvous/v1\n"...)
	b = append(b, Fold(channel)...)
	b = append(b, '\n')
	b = append(b, secret...)
	return key.NewSecretKey(blake3.Sum256(b))
}

// announce publishes addr as a way into the channel, and keeps
// publishing it: the service republishes on its own, and a record that
// stopped being refreshed expires, so a channel whose members have all
// gone quiet stops advertising a way in rather than advertising a dead
// one.
//
// The record is written under the channel's key while the address in it
// is the member's own, which is what makes one lookup enough: the
// resolver hands back both.
func (r *rendezvous) announce(name string, secret []byte, id key.EndpointID, addr netaddr.EndpointAddr) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.announced[name]; ok {
		return nil
	}
	pub, err := iroh.N0PkarrPublisher(rendezvousKey(name, secret), nil)
	if err != nil {
		return fmt.Errorf("announce %s: %w", name, err)
	}
	data := dns.NewEndpointData(addr.Addrs()...)
	user, err := dns.NewUserData(id.String())
	if err != nil {
		pub.Close()
		return fmt.Errorf("announce %s: %w", name, err)
	}
	data = data.WithUserData(&user)
	pub.Publish(data)
	r.announced[name] = pub
	return nil
}

// find resolves a channel's rendezvous record into a peer to bootstrap
// from. The record names the announcing member in its user data and
// carries that member's addresses, so what comes back is dialable as it
// stands.
func (r *rendezvous) find(ctx context.Context, name string, secret []byte) (netaddr.EndpointAddr, error) {
	res, err := iroh.NewPkarrResolver(iroh.N0DNSPkarrRelayProd, nil)
	if err != nil {
		return netaddr.EndpointAddr{}, fmt.Errorf("find %s: %w", name, err)
	}
	id := rendezvousKey(name, secret).Public().EndpointID()
	for item, err := range res.Resolve(ctx, id) {
		if err != nil {
			continue
		}
		info := item.EndpointInfo()
		u := info.Data.UserData()
		if u == nil {
			continue
		}
		member, err := key.ParseEndpointID(u.String())
		if err != nil {
			// A record under this key that does not name a member is
			// not a record this package wrote.
			continue
		}
		return netaddr.NewEndpointAddr(member, info.Data.Addrs()...), nil
	}
	return netaddr.EndpointAddr{}, fmt.Errorf("find %s: %w", name, ErrNoRendezvous)
}

// close stops announcing every channel.
func (r *rendezvous) close() {
	r.mu.Lock()
	defer r.mu.Unlock()
	for name, pub := range r.announced {
		pub.Close()
		delete(r.announced, name)
	}
}

// stop stops announcing one channel, which a node does when it parts.
func (r *rendezvous) stop(name string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if pub, ok := r.announced[name]; ok {
		pub.Close()
		delete(r.announced, name)
	}
}

// findTimeout bounds a rendezvous lookup. A joiner that cannot be told
// where the channel is within this should hear so, rather than wait on
// a name nobody has announced.
const findTimeout = 10 * time.Second

// joinTimeout is how long a join waits for a bootstrap peer to answer
// before going on without one. See [Node.subscribe].
const joinTimeout = 10 * time.Second

// seekInterval is how long a channel with no neighbors waits before
// looking for a way in again, and seekMaxInterval is how far that wait
// is allowed to grow. A channel nobody else is on is the ordinary case
// for the first member, so the wait backs off rather than asking a
// public name service the same question forever.
//
// seekWatchInterval is how often a channel that has neighbors checks
// that it still does. It is the cost of noticing, paid forever by
// every channel, so it is kept well below presenceTimeout and no
// lower: losing the last neighbor is rare, and nothing is gained by
// learning of it in under a second.
//
// seekMergeInterval is how often such a channel looks for a member it
// is not already meshed with, which is how two pockets of the same
// channel find each other. Nothing detects a pocket, so this is paid
// whether or not there is one; at five minutes it is a fraction of
// what presence costs at thirty seconds.
const (
	seekInterval      = 5 * time.Second
	seekMaxInterval   = 5 * time.Minute
	seekWatchInterval = 15 * time.Second
	seekMergeInterval = 5 * time.Minute
)
