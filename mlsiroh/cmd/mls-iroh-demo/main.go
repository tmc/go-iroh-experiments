// Mls-iroh-demo runs an MLS group over iroh in one process, showing
// both ways into it.
//
// Bob publishes a key package to his own directory; alice fetches it
// over a real iroh connection, creates a group, commits his addition,
// and delivers the welcome; bob joins and reads an encrypted message.
// Then carol, whom nobody adds, fetches the group info alice publishes
// to her endpoint id alone and commits herself in.
//
// Usage:
//
//	mls-iroh-demo [-v]
//
// The -v flag prints the endpoint ids and the bytes a relay would see.
//
// Every line of group logic here is a github.com/tmc/mls call. Package
// mlsiroh supplies only the transport: FetchKeyPackage, DeliverWelcome
// and FetchGroupInfo.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/netip"
	"os"
	"time"

	"github.com/tmc/go-iroh-experiments/mlsiroh"
	"github.com/tmc/go-iroh/iroh"
	"github.com/tmc/go-iroh/key"
	"github.com/tmc/mls"
)

var verbose = flag.Bool("v", false, "print endpoint ids and the relay's view of a message")

func main() {
	log.SetFlags(0)
	log.SetPrefix("mls-iroh-demo: ")
	flag.Parse()
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	alice, err := newPeer(ctx)
	if err != nil {
		return err
	}
	defer alice.close()
	bob, err := newPeer(ctx)
	if err != nil {
		return err
	}
	defer bob.close()

	if *verbose {
		fmt.Printf("alice %v\nbob   %v\n\n", alice.ep.ID(), bob.ep.ID())
	}

	// Bob publishes one key package. It is his to serve: there is no
	// shared directory, which is what makes the consume-once rule
	// enforceable.
	if err := bob.dir.Add(bob.client.KeyPackage); err != nil {
		return err
	}

	// Alice fetches it. The binding in the key package is signed by
	// bob's endpoint key, which the QUIC handshake already proved,
	// so there is nothing else to check it against.
	kp, err := mlsiroh.FetchKeyPackage(ctx, alice.ep, bob.ep.Addr(), mlsiroh.Suite)
	if err != nil {
		return fmt.Errorf("fetching bob's key package: %w", err)
	}
	id, err := mlsiroh.Verify(kp, time.Now())
	if err != nil {
		return err
	}
	fmt.Printf("alice fetched a key package bound to %v\n", id.Short())

	// Alice creates the group and commits bob's addition.
	groupID := []byte("mls-iroh-demo")
	g, err := alice.client.NewGroup(groupID, nil)
	if err != nil {
		return err
	}
	next, _, welcome, err := g.Commit([]*mls.Proposal{{
		Type: mls.ProposalTypeAdd,
		Add:  &mls.Add{KeyPackage: *kp},
	}})
	if err != nil {
		return fmt.Errorf("committing the add: %w", err)
	}
	fmt.Printf("alice committed: epoch %d -> %d\n", g.Epoch(), next.Epoch())

	// Deliver the welcome. Alice's commit is the only one for this
	// epoch, so it is accepted as soon as it is made. In a group
	// with other members the welcome would be held until the commit
	// was sequenced: see mlsiroh.DeliverWelcome.
	joined := make(chan *mls.Group, 1)
	errc := make(chan error, 1)
	go func() {
		for w := range bob.dir.Welcomes() {
			bg, err := bob.client.Join(w.Message, next.Tree)
			if err != nil {
				errc <- fmt.Errorf("bob joining: %w", err)
				return
			}
			fmt.Printf("bob got a welcome from %v and joined at epoch %d\n", w.From.Short(), bg.Epoch())
			joined <- bg
			return
		}
	}()
	if err := mlsiroh.DeliverWelcome(ctx, alice.ep, bob.ep.Addr(), welcome.Welcome); err != nil {
		return fmt.Errorf("delivering the welcome: %w", err)
	}

	var bobGroup *mls.Group
	select {
	case bobGroup = <-joined:
	case err := <-errc:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}

	if a, b := next.EpochAuthenticator(), bobGroup.EpochAuthenticator(); string(a) != string(b) {
		return fmt.Errorf("epoch authenticators differ: %x vs %x", a, b)
	}
	fmt.Printf("both agree on epoch authenticator %x\n", next.EpochAuthenticator()[:8])

	// One encrypted message.
	const text = "hello from alice, over iroh"
	msg, err := next.Protect(nil, []byte(text))
	if err != nil {
		return err
	}
	wire, err := mls.Marshal(msg)
	if err != nil {
		return err
	}
	if *verbose {
		h, err := mls.ParseHeader(wire)
		if err != nil {
			return err
		}
		fmt.Printf("\na relay sees: group %q epoch %d format %v, %d bytes of ciphertext\n",
			h.GroupID, h.Epoch, h.WireFormat, len(wire))
	}

	var received mls.Message
	if err := mls.Unmarshal(wire, &received); err != nil {
		return err
	}
	content, err := bobGroup.Unprotect(&received)
	if err != nil {
		return fmt.Errorf("bob decrypting: %w", err)
	}
	fmt.Printf("bob read: %q\n", content.Content.ApplicationData)

	// And bob can name the sender: her leaf resolves to the endpoint
	// he would dial to reach her.
	leaf := bobGroup.Tree.Leaf(next.Index)
	if leaf == nil {
		return fmt.Errorf("no leaf at index %d", next.Index)
	}
	sender, err := mlsiroh.VerifyLeaf(leaf)
	if err != nil {
		return err
	}
	fmt.Printf("bob resolves the sender to endpoint %v\n", sender.Short())
	if !sender.Equal(alice.ep.ID()) {
		fmt.Fprintln(os.Stderr, "but that is not alice")
		os.Exit(1)
	}

	// The other way in: carol is never added and gets no welcome. She
	// fetches the group and commits herself in. Alice's policy is the
	// whole access decision, and it is written in endpoint ids.
	carol, err := newPeer(ctx)
	if err != nil {
		return err
	}
	defer carol.close()

	info, err := next.GroupInfo()
	if err != nil {
		return err
	}
	if err := alice.dir.PublishGroupInfo(info.GroupInfo, func(id key.EndpointID) bool {
		return id.Equal(carol.ep.ID())
	}); err != nil {
		return err
	}
	fmt.Printf("\nalice publishes the group to %v and to nobody else\n", carol.ep.ID().Short())

	got, err := mlsiroh.FetchGroupInfo(ctx, carol.ep, alice.ep.Addr(), groupID)
	if err != nil {
		return fmt.Errorf("carol fetching the group info: %w", err)
	}
	carolGroup, commit, err := carol.client.JoinExternal(got, nil, nil)
	if err != nil {
		return fmt.Errorf("carol joining: %w", err)
	}
	// The group info named an epoch that carol's join ends, so it is
	// spent.
	alice.dir.WithdrawGroupInfo(groupID, info.GroupInfo.GroupContext.Epoch)

	// Carol's commit is a claim until the members apply it. Alice
	// published the group info for this epoch and so made no commit of
	// her own from it; carol's is the only one. Here the two members are
	// in this process, so they apply it directly.
	aliceAfter, _, err := next.Handle(commit)
	if err != nil {
		return fmt.Errorf("alice applying carol's commit: %w", err)
	}
	bobAfter, _, err := bobGroup.Handle(commit)
	if err != nil {
		return fmt.Errorf("bob applying carol's commit: %w", err)
	}
	a, b, c := aliceAfter.EpochAuthenticator(), bobAfter.EpochAuthenticator(), carolGroup.EpochAuthenticator()
	if string(a) != string(c) || string(b) != string(c) {
		return fmt.Errorf("epoch authenticators differ: %x %x %x", a, b, c)
	}
	fmt.Printf("carol committed herself in: epoch %d -> %d, all three agree on %x\n",
		next.Epoch(), carolGroup.Epoch(), c[:8])
	return nil
}

// A peer is one endpoint with a directory and an MLS client.
type peer struct {
	ep     *iroh.Endpoint
	dir    *mlsiroh.Directory
	router *iroh.Router
	client *mls.Client
}

func newPeer(ctx context.Context) (*peer, error) {
	sk, err := key.GenerateSecretKey()
	if err != nil {
		return nil, err
	}
	ep, err := iroh.Bind(ctx,
		iroh.WithSecretKey(sk),
		iroh.WithBindAddr(netip.AddrPortFrom(netip.IPv6Loopback(), 0)),
	)
	if err != nil {
		return nil, err
	}
	dir := mlsiroh.NewDirectory(sk, nil)
	router, err := iroh.NewRouter(ep, map[string]iroh.ProtocolHandler{mlsiroh.ALPN: dir.Handler()}, nil)
	if err != nil {
		ep.Shutdown(ctx)
		return nil, err
	}
	client, err := mlsiroh.NewClient(sk, time.Hour)
	if err != nil {
		router.Shutdown(ctx)
		ep.Shutdown(ctx)
		return nil, err
	}
	return &peer{ep: ep, dir: dir, router: router, client: client}, nil
}

func (p *peer) close() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	p.dir.Close()
	p.router.Shutdown(ctx)
	p.ep.Shutdown(ctx)
}
