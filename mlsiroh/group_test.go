package mlsiroh

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/tmc/go-iroh/iroh"
	"github.com/tmc/go-iroh/key"
	"github.com/tmc/mls"
)

// member is one endpoint with a directory and an MLS client.
type member struct {
	sk     key.SecretKey
	ep     *iroh.Endpoint
	dir    *Directory
	client *mls.Client
}

func newMember(t *testing.T, ctx context.Context) *member {
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
	client, err := NewClient(sk, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	return &member{sk: sk, ep: ep, dir: dir, client: client}
}

// TestGroup runs the whole composition over two real endpoints: bob
// publishes a key package, alice fetches it, creates a group, commits
// the add, delivers the welcome over iroh, and the two exchange an
// encrypted message.
//
// Every line of group logic here is an mls call. mlsiroh supplies only
// the two transport calls in the middle, which is the point of the
// experiment: the delivery service is small because MLS puts the hard
// part in the client.
func TestGroup(t *testing.T) {
	if testing.Short() {
		t.Skip("network test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	alice, bob := newMember(t, ctx), newMember(t, ctx)
	if err := bob.dir.Add(bob.client.KeyPackage); err != nil {
		t.Fatal(err)
	}

	// Alice fetches bob's key package over iroh. The binding proves
	// it is bob's: no directory, no certificate, no AS.
	kp, err := FetchKeyPackage(ctx, alice.ep, bob.ep.Addr(), Suite)
	if err != nil {
		t.Fatal(err)
	}
	if id, err := Verify(kp, time.Now()); err != nil || !id.Equal(bob.ep.ID()) {
		t.Fatalf("fetched key package names %v (%v), want %v", id, err, bob.ep.ID())
	}

	// Alice creates the group and commits bob's addition.
	g, err := alice.client.NewGroup([]byte("mlsiroh test group"), nil)
	if err != nil {
		t.Fatal(err)
	}
	next, _, welcome, err := g.Commit([]*mls.Proposal{{
		Type: mls.ProposalTypeAdd,
		Add:  &mls.Add{KeyPackage: *kp},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if welcome == nil {
		t.Fatal("commit adding a member produced no welcome")
	}

	// The commit is alice's own, so it is accepted the moment it is
	// created; in a group with other members it would have to be
	// sequenced first, and the welcome held until it won. See
	// DeliverWelcome.
	welcomes := make(chan Welcome, 1)
	go func() {
		for w := range bob.dir.Welcomes() {
			welcomes <- w
			return
		}
	}()
	if err := DeliverWelcome(ctx, alice.ep, bob.ep.Addr(), welcome.Welcome); err != nil {
		t.Fatal(err)
	}

	var got Welcome
	select {
	case got = <-welcomes:
	case <-ctx.Done():
		t.Fatal("timed out waiting for the welcome")
	}
	if !got.From.Equal(alice.ep.ID()) {
		t.Fatalf("welcome came from %v, want %v", got.From, alice.ep.ID())
	}

	// Bob joins from the welcome alone plus the tree it names.
	bobGroup, err := bob.client.Join(got.Message, next.Tree)
	if err != nil {
		t.Fatal(err)
	}
	if bobGroup.Epoch() != next.Epoch() {
		t.Fatalf("bob is in epoch %d, alice in %d", bobGroup.Epoch(), next.Epoch())
	}

	// Both sides agree on the epoch authenticator, which is the
	// check that they are in the same group and not merely running
	// the same code.
	if string(bobGroup.EpochAuthenticator()) != string(next.EpochAuthenticator()) {
		t.Fatal("epoch authenticators differ: the two are not in the same group")
	}

	// And a message crosses, encrypted.
	msg, err := next.Protect(nil, []byte("hello over iroh"))
	if err != nil {
		t.Fatal(err)
	}
	wire, err := mls.Marshal(msg)
	if err != nil {
		t.Fatal(err)
	}
	// The relay's view: a header, and nothing else.
	h, err := mls.ParseHeader(wire)
	if err != nil {
		t.Fatal(err)
	}
	if h.GroupID == nil || string(h.GroupID) != "mlsiroh test group" {
		t.Fatalf("ParseHeader group = %q", h.GroupID)
	}
	if h.WireFormat != mls.WireFormatPrivateMessage {
		t.Fatalf("application message wire format = %v", h.WireFormat)
	}

	var received mls.Message
	if err := mls.Unmarshal(wire, &received); err != nil {
		t.Fatal(err)
	}
	content, err := bobGroup.Unprotect(&received)
	if err != nil {
		t.Fatal(err)
	}
	if string(content.Content.ApplicationData) != "hello over iroh" {
		t.Fatalf("bob read %q", content.Content.ApplicationData)
	}

	// Bob resolves alice's leaf back to her endpoint, which closes
	// the loop: the member he is talking to is the endpoint he
	// would dial.
	leaf := bobGroup.Tree.Leaf(next.Index)
	if leaf == nil {
		t.Fatal("alice has no leaf in bob's tree")
	}
	id, err := VerifyLeaf(leaf)
	if err != nil {
		t.Fatal(err)
	}
	if !id.Equal(alice.ep.ID()) {
		t.Fatalf("alice's leaf names %v, want %v", id, alice.ep.ID())
	}
}

// TestExternalJoin is the other way into a group: carol is never added
// by a member and never receives a Welcome. She fetches the group's
// GroupInfo over iroh and commits herself in, which is what the
// external_pub extension is for (RFC 9420, Section 12.4.3.2).
//
// The policy is the whole access decision, and it is expressed in the
// one term iroh gives us for free: the caller's endpoint id. There is
// no token to mint and no invite to deliver.
func TestExternalJoin(t *testing.T) {
	if testing.Short() {
		t.Skip("network test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	alice, carol := newMember(t, ctx), newMember(t, ctx)

	groupID := []byte("mlsiroh external join")
	g, err := alice.client.NewGroup(groupID, nil)
	if err != nil {
		t.Fatal(err)
	}

	// Alice publishes the group to carol and to nobody else.
	info, err := g.GroupInfo()
	if err != nil {
		t.Fatal(err)
	}
	if err := alice.dir.PublishGroupInfo(info.GroupInfo, func(id key.EndpointID) bool {
		return id.Equal(carol.ep.ID())
	}); err != nil {
		t.Fatal(err)
	}

	// An endpoint the policy does not admit cannot tell the group from
	// one that does not exist.
	stranger := newMember(t, ctx)
	_, err = FetchGroupInfo(ctx, stranger.ep, alice.ep.Addr(), groupID)
	var e *Error
	if !errors.As(err, &e) || e.Status != StatusNotFound {
		t.Fatalf("stranger fetched the group info: %v", err)
	}

	got, err := FetchGroupInfo(ctx, carol.ep, alice.ep.Addr(), groupID)
	if err != nil {
		t.Fatal(err)
	}

	// Carol joins from the group info alone. The ratchet tree rides in
	// the group info, so she needs nothing else from the network.
	carolGroup, commit, err := carol.client.JoinExternal(got, nil, nil)
	if err != nil {
		t.Fatal(err)
	}

	// Alice applies carol's commit. Until she does, carol is not in the
	// group: JoinExternal produces a claim, not a membership.
	next, _, err := g.Handle(commit)
	if err != nil {
		t.Fatal(err)
	}
	if next.Epoch() != carolGroup.Epoch() {
		t.Fatalf("alice is in epoch %d, carol in %d", next.Epoch(), carolGroup.Epoch())
	}
	if string(next.EpochAuthenticator()) != string(carolGroup.EpochAuthenticator()) {
		t.Fatal("epoch authenticators differ: the two are not in the same group")
	}

	// The group info described an epoch that the join ended, so it is
	// spent. Alice withdraws it and publishes the new one.
	alice.dir.WithdrawGroupInfo(groupID, info.GroupInfo.GroupContext.Epoch)

	// And carol can speak in the group she committed herself into.
	msg, err := carolGroup.Protect(nil, []byte("carol, self-added"))
	if err != nil {
		t.Fatal(err)
	}
	content, err := next.Unprotect(msg)
	if err != nil {
		t.Fatal(err)
	}
	if string(content.Content.ApplicationData) != "carol, self-added" {
		t.Fatalf("alice read %q", content.Content.ApplicationData)
	}

	// Alice resolves the member who let herself in back to the endpoint
	// her policy admitted.
	leaf := next.Tree.Leaf(carolGroup.Index)
	if leaf == nil {
		t.Fatal("carol has no leaf in alice's tree")
	}
	id, err := VerifyLeaf(leaf)
	if err != nil {
		t.Fatal(err)
	}
	if !id.Equal(carol.ep.ID()) {
		t.Fatalf("the new leaf names %v, want %v", id, carol.ep.ID())
	}
}
