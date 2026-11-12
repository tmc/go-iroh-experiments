package mlsiroh

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/tmc/go-iroh/iroh"
	"github.com/tmc/go-iroh/key"
	"github.com/tmc/go-iroh/netaddr"
	"github.com/tmc/mls"
)

// node is one endpoint running a directory.
type node struct {
	sk  key.SecretKey
	ep  *iroh.Endpoint
	dir *Directory
}

func (n *node) addr() netaddr.EndpointAddr { return n.ep.Addr() }

// newNode returns one in-process node on IPv6 loopback with its
// directory registered under ALPN.
func newNode(t *testing.T, ctx context.Context) *node {
	t.Helper()
	sk, err := key.GenerateSecretKey()
	if err != nil {
		t.Fatal(err)
	}
	ep, err := iroh.Bind(ctx,
		iroh.WithSecretKey(sk),
		iroh.WithBindAddr(netip.AddrPortFrom(netip.IPv6Loopback(), 0)),
	)
	if err != nil {
		t.Fatal(err)
	}
	dir := NewDirectory(sk, nil)
	router, err := iroh.NewRouter(ep, map[string]iroh.ProtocolHandler{ALPN: dir.Handler()}, nil)
	if err != nil {
		ep.Shutdown(ctx)
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		dir.Close()
		router.Shutdown(ctx)
		ep.Shutdown(ctx)
	})
	return &node{sk: sk, ep: ep, dir: dir}
}

// publish adds n key packages to the node's pool.
func (n *node) publish(t *testing.T, count int) {
	t.Helper()
	for range count {
		kp, _ := newKeyPackage(t, n.sk)
		if err := n.dir.Add(kp); err != nil {
			t.Fatal(err)
		}
	}
}

func TestNetworkFetchKeyPackage(t *testing.T) {
	if testing.Short() {
		t.Skip("network test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	alice, bob := newNode(t, ctx), newNode(t, ctx)
	bob.publish(t, 2)

	kp, err := FetchKeyPackage(ctx, alice.ep, bob.addr(), Suite)
	if err != nil {
		t.Fatal(err)
	}
	// The whole thesis: the key package alice fetched names the
	// endpoint she connected to, proved by the transport alone.
	id, err := Verify(kp, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if !id.Equal(bob.ep.ID()) {
		t.Fatalf("key package names %v, connected to %v", id, bob.ep.ID())
	}
	if got := bob.dir.Len(); got != 1 {
		t.Fatalf("pool has %d left, want 1", got)
	}

	// The second fetch takes the last one; the third is exhausted.
	if _, err := FetchKeyPackage(ctx, alice.ep, bob.addr(), Suite); err != nil {
		t.Fatal(err)
	}
	_, err = FetchKeyPackage(ctx, alice.ep, bob.addr(), Suite)
	var e *Error
	if !errors.As(err, &e) || e.Status != StatusExhausted {
		t.Fatalf("third fetch = %v, want exhausted", err)
	}
}

// TestNetworkConsumeOnce is the property a shared last-write-wins
// directory cannot provide: concurrent fetches never hand out the same
// key package twice. The rate limits are lifted so that what stops the
// last fetch is the empty pool.
func TestNetworkConsumeOnce(t *testing.T) {
	if testing.Short() {
		t.Skip("network test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	alice, bob := newNode(t, ctx), newNode(t, ctx)
	const n = 2 * defaultKeyPackageRate
	bob.publish(t, n)
	bob.dir.LimitKeyPackages(-1, -1, 0)

	type result struct {
		ref mls.HashReference
		err error
	}
	results := make(chan result, n+1)
	for range n + 1 {
		go func() {
			kp, err := FetchKeyPackage(ctx, alice.ep, bob.addr(), Suite)
			if err != nil {
				results <- result{err: err}
				return
			}
			ref, err := kp.Ref()
			results <- result{ref: ref, err: err}
		}()
	}

	seen := make(map[string]bool)
	var exhausted int
	for range n + 1 {
		r := <-results
		if r.err != nil {
			var e *Error
			if !errors.As(r.err, &e) || e.Status != StatusExhausted {
				t.Fatalf("fetch = %v, want exhausted", r.err)
			}
			exhausted++
			continue
		}
		if seen[string(r.ref)] {
			t.Fatalf("key package %x served twice", []byte(r.ref))
		}
		seen[string(r.ref)] = true
	}
	if len(seen) != n || exhausted != 1 {
		t.Fatalf("%d distinct key packages and %d exhausted, want %d and 1", len(seen), exhausted, n)
	}
	if left := bob.dir.Len(); left != 0 {
		t.Fatalf("pool holds %d after %d fetches of %d", left, n+1, n)
	}
	// A directory that forgot would serve them again.
	for ref := range seen {
		if _, ok, err := bob.dir.journal.Lookup(mls.HashReference(ref)); err != nil || !ok {
			t.Fatalf("ref %x not journaled", ref)
		}
	}
}

// TestNetworkWelcomeNotAddressed checks that a Welcome naming a key
// package this directory never issued is refused, and refused with the
// same status as anything else the caller may not have: the response
// must not tell a prober whether a given key package reference is ours.
func TestNetworkWelcomeNotAddressed(t *testing.T) {
	if testing.Short() {
		t.Skip("network test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	alice, bob := newNode(t, ctx), newNode(t, ctx)
	bob.publish(t, 1)

	// A Welcome naming a key package bob never issued.
	w := &mls.Welcome{
		CipherSuite: Suite,
		Secrets: []mls.EncryptedGroupSecrets{
			{NewMember: mls.HashReference("not bob's key package")},
		},
	}
	err := DeliverWelcome(ctx, alice.ep, bob.addr(), w)
	var e *Error
	if !errors.As(err, &e) || e.Status != StatusNotFound {
		t.Fatalf("DeliverWelcome = %v, want not_found", err)
	}
}

func TestNetworkGroupInfoPolicy(t *testing.T) {
	if testing.Short() {
		t.Skip("network test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	alice, bob := newNode(t, ctx), newNode(t, ctx)

	// An unknown group is not found.
	_, err := FetchGroupInfo(ctx, alice.ep, bob.addr(), []byte("nope"))
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("fetch of an unknown group = %v, want not_found", err)
	}

	info := newGroupInfo(t, bob.sk, "g", 0)

	// A GroupInfo missing either extension is refused outright.
	for _, ext := range []mls.ExtensionType{mls.ExtensionTypeRatchetTree, mls.ExtensionTypeExternalPub} {
		without := *info
		without.Extensions = nil
		for _, e := range info.Extensions {
			if e.Type != ext {
				without.Extensions = append(without.Extensions, e)
			}
		}
		if err := bob.dir.PublishGroupInfo(&without, nil); !errors.Is(err, ErrInvalidGroupInfo) {
			t.Fatalf("PublishGroupInfo without extension %v = %v, want ErrInvalidGroupInfo", ext, err)
		}
	}

	// Published with a nil policy, which admits nobody. An
	// unauthorized caller sees not_found, not a distinct status:
	// the endpoint must not confirm the group exists.
	if err := bob.dir.PublishGroupInfo(info, nil); err != nil {
		t.Fatal(err)
	}
	_, err = FetchGroupInfo(ctx, alice.ep, bob.addr(), []byte("g"))
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("fetch under a nil policy = %v, want not_found", err)
	}

	// Admitted, the caller gets it back byte-identical.
	if err := bob.dir.PublishGroupInfo(info, func(id key.EndpointID) bool {
		return id.Equal(alice.ep.ID())
	}); err != nil {
		t.Fatal(err)
	}
	got, err := FetchGroupInfo(ctx, alice.ep, bob.addr(), []byte("g"))
	if err != nil {
		t.Fatal(err)
	}
	want, err := mls.Marshal(info)
	if err != nil {
		t.Fatal(err)
	}
	gotBytes, err := mls.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	if string(gotBytes) != string(want) {
		t.Fatal("group info did not survive the transport byte-identically")
	}

	// Withdrawn, it is gone again.
	bob.dir.WithdrawGroupInfo([]byte("g"), info.GroupContext.Epoch)
	if _, err := FetchGroupInfo(ctx, alice.ep, bob.addr(), []byte("g")); !errors.Is(err, ErrNotFound) {
		t.Fatalf("fetch after withdrawal = %v, want not_found", err)
	}
}

// newGroupInfo returns the GroupInfo of a new group founded by the
// endpoint sk names, advanced by the given number of empty commits.
func newGroupInfo(t *testing.T, sk key.SecretKey, groupID string, commits int) *mls.GroupInfo {
	t.Helper()
	c, err := NewClient(sk, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	g, err := c.NewGroup([]byte(groupID), nil)
	if err != nil {
		t.Fatal(err)
	}
	for range commits {
		if g, _, _, err = g.Commit(nil); err != nil {
			t.Fatal(err)
		}
	}
	info, err := g.GroupInfo()
	if err != nil {
		t.Fatal(err)
	}
	return info.GroupInfo
}

func TestNetworkWrongSuite(t *testing.T) {
	if testing.Short() {
		t.Skip("network test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	alice, bob := newNode(t, ctx), newNode(t, ctx)
	bob.publish(t, 1)

	_, err := FetchKeyPackage(ctx, alice.ep, bob.addr(), mls.P256AES128GCMSHA256P256)
	var e *Error
	if !errors.As(err, &e) || e.Status != StatusUnsupported {
		t.Fatalf("fetch of an unsupported suite = %v, want unsupported", err)
	}
}
