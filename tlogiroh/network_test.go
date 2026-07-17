package tlogiroh

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"net/netip"
	"testing"
	"time"

	"github.com/tmc/go-iroh/blobs"
	"github.com/tmc/go-iroh/docs"
	"github.com/tmc/go-iroh/gossip"
	"github.com/tmc/go-iroh/iroh"
	"github.com/tmc/go-iroh/netaddr"
	"golang.org/x/mod/sumdb/note"
)

// testNode is one in-process iroh endpoint with gossip registered, plus any
// extra protocol handlers.
type testNode struct {
	ep     *iroh.Endpoint
	gossip *gossip.Gossip
	router *iroh.Router
}

func newTestNode(t *testing.T, ctx context.Context, extra map[string]iroh.ProtocolHandler) *testNode {
	t.Helper()
	ep, err := iroh.Bind(ctx, iroh.WithBindAddr(netip.AddrPortFrom(netip.IPv6Loopback(), 0)))
	if err != nil {
		t.Fatal(err)
	}
	gg := gossip.NewGossip(ep)
	handlers := map[string]iroh.ProtocolHandler{gossip.ALPN: gg.Handler()}
	maps.Copy(handlers, extra)
	router, err := iroh.NewRouter(ep, handlers, nil)
	if err != nil {
		_ = ep.Shutdown(ctx)
		t.Fatal(err)
	}
	n := &testNode{ep: ep, gossip: gg, router: router}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = n.router.Shutdown(ctx)
		n.gossip.Shutdown(ctx)
		_ = n.ep.Shutdown(ctx)
	})
	return n
}

func (n *testNode) addr() netaddr.EndpointAddr {
	return netaddr.NewEndpointAddr(n.ep.ID()).WithIP(n.ep.LocalAddr())
}

func (n *testNode) join(t *testing.T, ctx context.Context, bootstrap []netaddr.EndpointAddr) *gossip.Topic {
	t.Helper()
	topic, err := n.gossip.Subscribe(ctx, TopicID(testOrigin), bootstrap)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = topic.Close() })
	return topic
}

// blobStreamHandler serves every stream of a blobs-ALPN connection from a
// local store.
type blobStreamHandler struct {
	store blobs.Store
}

func (h blobStreamHandler) Accept(ctx context.Context, conn *iroh.Conn) error {
	return blobs.ServeBlobStreams(ctx, func(ctx context.Context) (blobs.BidiStream, error) {
		return conn.AcceptStream(ctx)
	}, h.store)
}

// TestNetworkCosignEquivocation runs the full flow over real loopback
// endpoints: the operator serves blobs, docs, and gossip; a witness
// replicates the timeline, cosigns announcements, and rebroadcasts; a
// client with a K=1 policy accepts cosigned checkpoints; and a split view
// injected by a fourth node is detected and flooded as an equivocation
// proof.
func TestNetworkCosignEquivocation(t *testing.T) {
	if testing.Short() {
		t.Skip("network test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	op, opVerifier, _ := newTestLog(t)
	opNode := newTestNode(t, ctx, map[string]iroh.ProtocolHandler{
		blobs.ALPN: blobStreamHandler{store: op.Blobs()},
		docs.ALPN:  &docs.Handler{Store: op.Doc(), BlobStore: op.Blobs()},
	})
	witnessNode := newTestNode(t, ctx, nil)
	clientNode := newTestNode(t, ctx, nil)
	evilNode := newTestNode(t, ctx, nil)

	// The witness and client each keep their own replica of the timeline
	// and fetch blobs from the operator on demand.
	witnessDoc := docs.NewMemoryStore()
	witnessSrc := Source{
		Doc:       witnessDoc,
		Namespace: op.Namespace(),
		Author:    op.Author(),
		Get:       DialBlobGetter(witnessNode.ep, opNode.addr()),
	}
	clientDoc := docs.NewMemoryStore()
	clientSrc := Source{
		Doc:       clientDoc,
		Namespace: op.Namespace(),
		Author:    op.Author(),
		Get:       DialBlobGetter(clientNode.ep, opNode.addr()),
	}
	resync := func() {
		t.Helper()
		for _, r := range []struct {
			ep    *iroh.Endpoint
			store *docs.MemoryStore
		}{{witnessNode.ep, witnessDoc}, {clientNode.ep, clientDoc}} {
			if _, err := docs.Sync(ctx, r.ep, opNode.addr(), op.Namespace(), r.store, nil, docs.DefaultSyncConfig()); err != nil {
				t.Fatalf("docs sync: %v", err)
			}
		}
	}

	witness, witnessVerifier := newTestWitness(t, "witness.net", opVerifier, witnessSrc)
	policy, err := NewPolicy(testOrigin, opVerifier, []note.Verifier{witnessVerifier}, 1)
	if err != nil {
		t.Fatal(err)
	}
	client := NewClient(policy, clientSrc)

	opTopic := opNode.join(t, ctx, nil)
	bootstrap := []netaddr.EndpointAddr{opNode.addr()}
	witnessTopic := witnessNode.join(t, ctx, bootstrap)
	clientTopic := clientNode.join(t, ctx, bootstrap)
	evilTopic := evilNode.join(t, ctx, bootstrap)
	for _, topic := range []*gossip.Topic{witnessTopic, clientTopic, evilTopic, opTopic} {
		if err := topic.Joined(ctx); err != nil {
			t.Fatalf("topic join: %v", err)
		}
	}

	go witness.Run(ctx, witnessTopic)

	heads := make(chan Checkpoint, 16)
	equivs := make(chan *EquivocationError, 16)
	go func() {
		for cp, err := range client.Watch(ctx, clientTopic) {
			if equiv, ok := errors.AsType[*EquivocationError](err); ok {
				equivs <- equiv
				continue
			}
			if err == nil {
				heads <- cp
			}
		}
	}()

	waitHead := func(size int64) {
		t.Helper()
		for {
			select {
			case cp := <-heads:
				if cp.Tree.N == size {
					return
				}
			case <-ctx.Done():
				t.Fatalf("timed out waiting for accepted checkpoint of size %d", size)
			}
		}
	}

	// A published checkpoint reaches the client only through the witness:
	// the operator announcement alone fails the K=1 policy.
	appendAndPublish(t, op, 5)
	resync()
	if err := op.Announce(ctx, opTopic); err != nil {
		t.Fatal(err)
	}
	waitHead(5)

	// Growing the log exercises the witness and client consistency proofs
	// over the network.
	appendAndPublish(t, op, 12)
	resync()
	if err := op.Announce(ctx, opTopic); err != nil {
		t.Fatal(err)
	}
	waitHead(12)

	// A split view at the same size, announced from another node, must
	// surface as a verifiable equivocation proof at the client.
	twin, err := NewOperator(testOrigin, op.signer)
	if err != nil {
		t.Fatal(err)
	}
	for twin.Size() < 12 {
		if _, err := twin.Append(ctx, fmt.Appendf(nil, `{"twin":%d}`, twin.Size())); err != nil {
			t.Fatal(err)
		}
	}
	twinMsg, err := twin.Publish(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := evilTopic.Broadcast(ctx, envelope(envCheckpoint, twinMsg)); err != nil {
		t.Fatal(err)
	}

	select {
	case equiv := <-equivs:
		size, err := VerifyEquivocation(equiv.Proof, testOrigin, opVerifier)
		if err != nil {
			t.Fatalf("flooded proof does not verify: %v", err)
		}
		if size != 12 {
			t.Fatalf("equivocated size = %d, want 12", size)
		}
	case <-ctx.Done():
		t.Fatal("timed out waiting for equivocation proof")
	}

	// The split view must not have advanced anyone's head.
	if head, ok := client.Head(); !ok || head.Tree.N != 12 {
		t.Fatalf("client head after equivocation = %+v %v, want size 12", head, ok)
	}
	if head, ok := witness.Head(); !ok || head.Tree.N != 12 {
		t.Fatalf("witness head after equivocation = %+v %v, want size 12", head, ok)
	}
}

// TestNetworkStaleAnnounceRetry reproduces the multi-process race: the
// operator announces growth before the witness and client replicas have
// synced the new tiles. Gossip deduplicates the byte-identical
// re-announcement of a deterministic checkpoint, so each peer sees it once;
// the witness and client must park it and retry internally once their
// replicas catch up.
func TestNetworkStaleAnnounceRetry(t *testing.T) {
	if testing.Short() {
		t.Skip("network test")
	}
	defer func(d time.Duration) { staleRetryInterval = d }(staleRetryInterval)
	staleRetryInterval = 200 * time.Millisecond

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	op, opVerifier, _ := newTestLog(t)
	opNode := newTestNode(t, ctx, map[string]iroh.ProtocolHandler{
		blobs.ALPN: blobStreamHandler{store: op.Blobs()},
		docs.ALPN:  &docs.Handler{Store: op.Doc(), BlobStore: op.Blobs()},
	})
	witnessNode := newTestNode(t, ctx, nil)
	clientNode := newTestNode(t, ctx, nil)

	witnessDoc := docs.NewMemoryStore()
	witnessSrc := Source{
		Doc:       witnessDoc,
		Namespace: op.Namespace(),
		Author:    op.Author(),
		Get:       DialBlobGetter(witnessNode.ep, opNode.addr()),
	}
	clientDoc := docs.NewMemoryStore()
	clientSrc := Source{
		Doc:       clientDoc,
		Namespace: op.Namespace(),
		Author:    op.Author(),
		Get:       DialBlobGetter(clientNode.ep, opNode.addr()),
	}
	resync := func() {
		t.Helper()
		for _, r := range []struct {
			ep    *iroh.Endpoint
			store *docs.MemoryStore
		}{{witnessNode.ep, witnessDoc}, {clientNode.ep, clientDoc}} {
			if _, err := docs.Sync(ctx, r.ep, opNode.addr(), op.Namespace(), r.store, nil, docs.DefaultSyncConfig()); err != nil {
				t.Fatalf("docs sync: %v", err)
			}
		}
	}

	witness, witnessVerifier := newTestWitness(t, "witness.net", opVerifier, witnessSrc)
	policy, err := NewPolicy(testOrigin, opVerifier, []note.Verifier{witnessVerifier}, 1)
	if err != nil {
		t.Fatal(err)
	}
	client := NewClient(policy, clientSrc)

	opTopic := opNode.join(t, ctx, nil)
	bootstrap := []netaddr.EndpointAddr{opNode.addr()}
	witnessTopic := witnessNode.join(t, ctx, bootstrap)
	clientTopic := clientNode.join(t, ctx, bootstrap)
	for _, topic := range []*gossip.Topic{witnessTopic, clientTopic, opTopic} {
		if err := topic.Joined(ctx); err != nil {
			t.Fatalf("topic join: %v", err)
		}
	}

	go witness.Run(ctx, witnessTopic)
	heads := make(chan Checkpoint, 16)
	go func() {
		for cp, err := range client.Watch(ctx, clientTopic) {
			if err == nil {
				heads <- cp
			}
		}
	}()
	waitHead := func(size int64) {
		t.Helper()
		for {
			select {
			case cp := <-heads:
				if cp.Tree.N == size {
					return
				}
			case <-ctx.Done():
				t.Fatalf("timed out waiting for accepted checkpoint of size %d", size)
			}
		}
	}

	appendAndPublish(t, op, 5)
	resync()
	if err := op.Announce(ctx, opTopic); err != nil {
		t.Fatal(err)
	}
	waitHead(5)

	// Grow and announce exactly once, before the replicas sync: every
	// reader parks the checkpoint. Give the announcement time to arrive,
	// then sync and let the retries accept it.
	appendAndPublish(t, op, 12)
	if err := op.Announce(ctx, opTopic); err != nil {
		t.Fatal(err)
	}
	time.Sleep(time.Second)
	resync()
	waitHead(12)
}
