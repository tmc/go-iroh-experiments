package mlsiroh_test

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/netip"
	"os"
	"path/filepath"
	"sync/atomic"
	"time"

	"github.com/tmc/go-iroh-experiments/mlsiroh"
	"github.com/tmc/go-iroh/iroh"
	"github.com/tmc/go-iroh/key"
	"github.com/tmc/mls"
)

// Example shows one endpoint publishing a key package and another
// fetching it. The fetched package is bound to the endpoint it was
// fetched from, which is what removes the need for a separate
// authentication service.
func Example() {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Bob serves his own key packages.
	bob := serve(ctx, nil)
	defer bob.close()
	client, err := mlsiroh.NewClient(bob.sk, time.Hour)
	if err != nil {
		log.Fatal(err)
	}
	if err := bob.dir.Add(client.KeyPackage); err != nil {
		log.Fatal(err)
	}

	// Alice fetches it.
	alice := serve(ctx, nil)
	defer alice.close()
	kp, err := mlsiroh.FetchKeyPackage(ctx, alice.ep, bob.ep.Addr(), mlsiroh.Suite)
	if err != nil {
		log.Fatal(err)
	}
	id, err := mlsiroh.Verify(kp, time.Now())
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("key package is bound to bob:", id.Equal(bob.ep.ID()))

	// It was consumed: MLS means a key package to be used once.
	_, err = mlsiroh.FetchKeyPackage(ctx, alice.ep, bob.ep.Addr(), mlsiroh.Suite)
	fmt.Println("second fetch:", err)

	// Output:
	// key package is bound to bob: true
	// second fetch: fetch_key_package: exhausted
}

// node is an endpoint serving a directory.
type node struct {
	sk     key.SecretKey
	ep     *iroh.Endpoint
	dir    *mlsiroh.Directory
	router *iroh.Router
}

// serve starts an endpoint on loopback with a directory recording into
// j, which may be nil.
func serve(ctx context.Context, j mlsiroh.Journal) *node {
	sk, err := key.GenerateSecretKey()
	if err != nil {
		log.Fatal(err)
	}
	return serveKey(ctx, sk, j)
}

func serveKey(ctx context.Context, sk key.SecretKey, j mlsiroh.Journal) *node {
	ep, err := iroh.Bind(ctx,
		iroh.WithSecretKey(sk),
		iroh.WithBindAddr(netip.AddrPortFrom(netip.IPv6Loopback(), 0)),
	)
	if err != nil {
		log.Fatal(err)
	}
	dir := mlsiroh.NewDirectory(sk, j)
	router, err := iroh.NewRouter(ep, map[string]iroh.ProtocolHandler{mlsiroh.ALPN: dir.Handler()}, nil)
	if err != nil {
		log.Fatal(err)
	}
	return &node{sk: sk, ep: ep, dir: dir, router: router}
}

func (n *node) close() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	n.dir.Close()
	n.router.Shutdown(ctx)
	n.ep.Shutdown(ctx)
}

func ExampleDirectory_Add() {
	sk, err := key.GenerateSecretKey()
	if err != nil {
		log.Fatal(err)
	}
	dir := mlsiroh.NewDirectory(sk, nil)
	defer dir.Close()

	client, err := mlsiroh.NewClient(sk, time.Hour)
	if err != nil {
		log.Fatal(err)
	}
	if err := dir.Add(client.KeyPackage); err != nil {
		log.Fatal(err)
	}
	fmt.Println("pool:", dir.Len())

	// A directory serves only its own endpoint's key packages.
	other, err := key.GenerateSecretKey()
	if err != nil {
		log.Fatal(err)
	}
	stranger, err := mlsiroh.NewClient(other, time.Hour)
	if err != nil {
		log.Fatal(err)
	}
	err = dir.Add(stranger.KeyPackage)
	fmt.Println("another endpoint's:", errors.Is(err, mlsiroh.ErrWrongEndpoint))

	// Output:
	// pool: 1
	// another endpoint's: true
}

// ExampleOpenJournal shows the journal outliving a directory: a key
// package served before a restart is not served again after it.
func ExampleOpenJournal() {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	dir, err := os.MkdirTemp("", "mlsiroh")
	if err != nil {
		log.Fatal(err)
	}
	defer os.RemoveAll(dir)
	name := filepath.Join(dir, "journal")

	j, err := mlsiroh.OpenJournal(name)
	if err != nil {
		log.Fatal(err)
	}
	bob := serve(ctx, j)
	client, err := mlsiroh.NewClient(bob.sk, time.Hour)
	if err != nil {
		log.Fatal(err)
	}
	if err := bob.dir.Add(client.KeyPackage); err != nil {
		log.Fatal(err)
	}
	alice := serve(ctx, nil)
	defer alice.close()
	if _, err := mlsiroh.FetchKeyPackage(ctx, alice.ep, bob.ep.Addr(), mlsiroh.Suite); err != nil {
		log.Fatal(err)
	}
	bob.close()
	j.Close()

	// Bob restarts and publishes the same key package again.
	j, err = mlsiroh.OpenJournal(name)
	if err != nil {
		log.Fatal(err)
	}
	defer j.Close()
	restarted := mlsiroh.NewDirectory(bob.sk, j)
	defer restarted.Close()
	err = restarted.Add(client.KeyPackage)
	fmt.Println("consumed:", errors.Is(err, mlsiroh.ErrConsumed))

	// Output:
	// consumed: true
}

func ExampleDirectory_LimitKeyPackages() {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	bob, alice := serve(ctx, nil), serve(ctx, nil)
	defer bob.close()
	defer alice.close()

	// Two key packages per endpoint per minute, and the default total.
	bob.dir.LimitKeyPackages(2, 0, time.Minute)
	for range 3 {
		c, err := mlsiroh.NewClient(bob.sk, time.Hour)
		if err != nil {
			log.Fatal(err)
		}
		if err := bob.dir.Add(c.KeyPackage); err != nil {
			log.Fatal(err)
		}
	}
	for range 3 {
		_, err := mlsiroh.FetchKeyPackage(ctx, alice.ep, bob.ep.Addr(), mlsiroh.Suite)
		fmt.Println(err)
	}
	fmt.Println("left:", bob.dir.Len())

	// Output:
	// <nil>
	// <nil>
	// fetch_key_package: exhausted
	// left: 1
}

func ExampleDirectory_AdmitKeyPackages() {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	bob, alice, stranger := serve(ctx, nil), serve(ctx, nil), serve(ctx, nil)
	defer bob.close()
	defer alice.close()
	defer stranger.close()

	c, err := mlsiroh.NewClient(bob.sk, time.Hour)
	if err != nil {
		log.Fatal(err)
	}
	if err := bob.dir.Add(c.KeyPackage); err != nil {
		log.Fatal(err)
	}
	// Bob expects to be added by alice and nobody else.
	bob.dir.AdmitKeyPackages(func(id key.EndpointID) bool { return id.Equal(alice.ep.ID()) })

	_, err = mlsiroh.FetchKeyPackage(ctx, stranger.ep, bob.ep.Addr(), mlsiroh.Suite)
	fmt.Println("stranger:", errors.Is(err, mlsiroh.ErrExhausted))
	_, err = mlsiroh.FetchKeyPackage(ctx, alice.ep, bob.ep.Addr(), mlsiroh.Suite)
	fmt.Println("alice:", err)

	// Output:
	// stranger: true
	// alice: <nil>
}

// ExampleDeliverWelcome shows the first way into a group: a member
// fetches the newcomer's key package, commits the Add, and delivers the
// Welcome, which the newcomer reads from [mlsiroh.Directory.Welcomes].
func ExampleDeliverWelcome() {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	alice, bob := serve(ctx, nil), serve(ctx, nil)
	defer alice.close()
	defer bob.close()

	bobClient, err := mlsiroh.NewClient(bob.sk, time.Hour)
	if err != nil {
		log.Fatal(err)
	}
	if err := bob.dir.Add(bobClient.KeyPackage); err != nil {
		log.Fatal(err)
	}

	aliceClient, err := mlsiroh.NewClient(alice.sk, time.Hour)
	if err != nil {
		log.Fatal(err)
	}
	g, err := aliceClient.NewGroup([]byte("example"), nil)
	if err != nil {
		log.Fatal(err)
	}
	kp, err := mlsiroh.FetchKeyPackage(ctx, alice.ep, bob.ep.Addr(), mlsiroh.Suite)
	if err != nil {
		log.Fatal(err)
	}
	next, _, welcome, err := g.Commit([]*mls.Proposal{{Type: mls.ProposalTypeAdd, Add: &mls.Add{KeyPackage: *kp}}})
	if err != nil {
		log.Fatal(err)
	}
	// Alice is the group's only committer, so her commit is accepted
	// as soon as she makes it, and the Welcome may go.
	if err := mlsiroh.DeliverWelcome(ctx, alice.ep, bob.ep.Addr(), welcome.Welcome); err != nil {
		log.Fatal(err)
	}

	for w := range bob.dir.Welcomes() {
		bg, err := bobClient.Join(w.Message, next.Tree)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println("from alice:", w.From.Equal(alice.ep.ID()))
		fmt.Println("epoch:", bg.Epoch())
		break
	}

	// Output:
	// from alice: true
	// epoch: 1
}

// ExampleDirectory_PublishGroupInfo shows the second way into a group:
// a member publishes the group to one endpoint, which fetches it and
// commits itself in.
func ExampleDirectory_PublishGroupInfo() {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	alice, carol := serve(ctx, nil), serve(ctx, nil)
	defer alice.close()
	defer carol.close()

	aliceClient, err := mlsiroh.NewClient(alice.sk, time.Hour)
	if err != nil {
		log.Fatal(err)
	}
	groupID := []byte("example")
	g, err := aliceClient.NewGroup(groupID, nil)
	if err != nil {
		log.Fatal(err)
	}
	info, err := g.GroupInfo()
	if err != nil {
		log.Fatal(err)
	}
	// One fetch, by carol. The caller is checked before the fetch is
	// spent, so nobody else's probe can spend it.
	var used atomic.Bool
	err = alice.dir.PublishGroupInfo(info.GroupInfo, func(id key.EndpointID) bool {
		return id.Equal(carol.ep.ID()) && used.CompareAndSwap(false, true)
	})
	if err != nil {
		log.Fatal(err)
	}

	got, err := mlsiroh.FetchGroupInfo(ctx, carol.ep, alice.ep.Addr(), groupID)
	if err != nil {
		log.Fatal(err)
	}
	carolClient, err := mlsiroh.NewClient(carol.sk, time.Hour)
	if err != nil {
		log.Fatal(err)
	}
	carolGroup, commit, err := carolClient.JoinExternal(got, nil, nil)
	if err != nil {
		log.Fatal(err)
	}
	next, _, err := g.Handle(commit)
	if err != nil {
		log.Fatal(err)
	}
	alice.dir.WithdrawGroupInfo(groupID, info.GroupInfo.GroupContext.Epoch)
	fmt.Println("epochs:", next.Epoch(), carolGroup.Epoch())

	_, err = mlsiroh.FetchGroupInfo(ctx, carol.ep, alice.ep.Addr(), groupID)
	fmt.Println("again:", errors.Is(err, mlsiroh.ErrNotFound))

	// Output:
	// epochs: 1 1
	// again: true
}

func ExampleVerify() {
	sk, err := key.GenerateSecretKey()
	if err != nil {
		log.Fatal(err)
	}
	client, err := mlsiroh.NewClient(sk, time.Hour)
	if err != nil {
		log.Fatal(err)
	}
	id, err := mlsiroh.Verify(client.KeyPackage, time.Now())
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(id.Equal(sk.Public().EndpointID()))

	// Output:
	// true
}

func ExampleVerifyLeaf() {
	sk, err := key.GenerateSecretKey()
	if err != nil {
		log.Fatal(err)
	}
	client, err := mlsiroh.NewClient(sk, time.Hour)
	if err != nil {
		log.Fatal(err)
	}
	g, err := client.NewGroup([]byte("example"), nil)
	if err != nil {
		log.Fatal(err)
	}
	id, err := mlsiroh.VerifyLeaf(g.Tree.Leaf(g.Index))
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(id.Equal(sk.Public().EndpointID()))

	// Output:
	// true
}

// ExampleLeaves finds the leaves an endpoint holds in a group, which an
// application can ask the committer to remove when an endpoint rejoins
// with a fresh signature key.
func ExampleLeaves() {
	alice, aliceID := newClient()
	bob, bobID := newClient()
	g, err := alice.NewGroup([]byte("example"), nil)
	if err != nil {
		log.Fatal(err)
	}
	next, _, _, err := g.Commit([]*mls.Proposal{{Type: mls.ProposalTypeAdd, Add: &mls.Add{KeyPackage: *bob.KeyPackage}}})
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("alice:", mlsiroh.Leaves(next.Tree, aliceID))
	fmt.Println("bob:", mlsiroh.Leaves(next.Tree, bobID))

	// Output:
	// alice: [0]
	// bob: [1]
}

// ExampleSignUpdate rotates bob's leaf signature key. Bob proposes the
// Update, alice commits it, and bob's new leaf still resolves to his
// endpoint.
func ExampleSignUpdate() {
	alice, _ := newClient()
	bob, bobID := newClient()
	g, err := alice.NewGroup([]byte("example"), nil)
	if err != nil {
		log.Fatal(err)
	}
	next, _, welcome, err := g.Commit([]*mls.Proposal{{Type: mls.ProposalTypeAdd, Add: &mls.Add{KeyPackage: *bob.KeyPackage}}})
	if err != nil {
		log.Fatal(err)
	}
	bg, err := bob.Join(welcome.Welcome, next.Tree.Clone())
	if err != nil {
		log.Fatal(err)
	}

	sigPriv, sigPub, err := mlsiroh.Suite.GenerateSignatureKeyPair()
	if err != nil {
		log.Fatal(err)
	}
	encPriv, encPub, err := mlsiroh.Suite.GenerateKeyPair()
	if err != nil {
		log.Fatal(err)
	}
	leaf := *bg.Tree.Leaf(bg.Index)
	leaf.SignatureKey, leaf.EncryptionKey = sigPub, encPub
	if err := mlsiroh.SignUpdate(bob.sk, sigPriv, &leaf, bg.Context.GroupID, bg.Index); err != nil {
		log.Fatal(err)
	}
	proposal, err := bg.ProposeUpdateKeys(&leaf, encPriv, sigPriv)
	if err != nil {
		log.Fatal(err)
	}
	if _, _, err := next.Handle(proposal); err != nil {
		log.Fatal(err)
	}
	after, _, _, err := next.Commit(nil)
	if err != nil {
		log.Fatal(err)
	}
	id, err := mlsiroh.VerifyLeaf(after.Tree.Leaf(bg.Index))
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("still bob:", id.Equal(bobID))

	// Output:
	// still bob: true
}

// client is an MLS client and the endpoint key it is bound to.
type client struct {
	*mls.Client
	sk key.SecretKey
}

func newClient() (*client, key.EndpointID) {
	sk, err := key.GenerateSecretKey()
	if err != nil {
		log.Fatal(err)
	}
	c, err := mlsiroh.NewClient(sk, time.Hour)
	if err != nil {
		log.Fatal(err)
	}
	return &client{Client: c, sk: sk}, sk.Public().EndpointID()
}

// ExampleSign binds a key package to an endpoint. Whichever endpoint
// key signs it is the one [mlsiroh.Verify] resolves it to.
func ExampleSign() {
	alice, _ := newClient()
	bob, err := key.GenerateSecretKey()
	if err != nil {
		log.Fatal(err)
	}
	if err := mlsiroh.Sign(bob, alice.SignaturePriv, alice.KeyPackage); err != nil {
		log.Fatal(err)
	}
	id, err := mlsiroh.Verify(alice.KeyPackage, time.Now())
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(id.Equal(bob.Public().EndpointID()))

	// Output:
	// true
}

// ExampleCapabilities shows that an mlsiroh member admits one credential
// type, the one binding a leaf to an endpoint.
func ExampleCapabilities() {
	fmt.Println(len(mlsiroh.Capabilities().Credentials))

	// Output:
	// 1
}

// ExampleMemoryJournal shows the consume-once rule a journal keeps: a
// key package re-signed with a new reference is still the init key
// that was served.
func ExampleMemoryJournal() {
	var j mlsiroh.MemoryJournal
	served := mlsiroh.Entry{Ref: mls.HashReference("ref-1"), InitKey: mls.HPKEPublicKey("init"), NotAfter: 1}
	if err := j.Record(served); err != nil {
		log.Fatal(err)
	}
	resigned := mlsiroh.Entry{Ref: mls.HashReference("ref-2"), InitKey: served.InitKey, NotAfter: 2}
	fresh := mlsiroh.Entry{Ref: mls.HashReference("ref-3"), InitKey: mls.HPKEPublicKey("other")}
	for _, e := range []mlsiroh.Entry{served, resigned, fresh} {
		ok, err := j.Consumed(e)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("%s: %v\n", e.Ref, ok)
	}

	// Output:
	// ref-1: true
	// ref-2: true
	// ref-3: false
}
