package mlsiroh

import (
	"context"
	"errors"
	"io"
	"net/netip"
	"testing"
	"time"

	"github.com/tmc/go-iroh/iroh"
	"github.com/tmc/go-iroh/key"
	"github.com/tmc/go-iroh/netaddr"
	"github.com/tmc/mls"
)

// TestGroupInfoIsBound checks that a fetched group info is the group
// that was asked for, signed by the endpoint that served it.
//
// Positive: a GroupInfo served by the endpoint that signed it, for the
// group that was asked for, is accepted.
// Negative controls, one decisive predicate each: (a) the same GroupInfo
// fetched under a different group id; (b) a GroupInfo signed by an
// endpoint other than the one serving it.
func TestGroupInfoIsBound(t *testing.T) {
	if testing.Short() {
		t.Skip("network test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	alice, bob := newNode(t, ctx), newNode(t, ctx)

	// Alice publishes her own group, signed by her own leaf.
	ac, err := NewClient(alice.sk, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	g, err := ac.NewGroup([]byte("real-group"), nil)
	if err != nil {
		t.Fatal(err)
	}
	info, err := g.GroupInfo()
	if err != nil {
		t.Fatal(err)
	}
	if err := alice.dir.PublishGroupInfo(info.GroupInfo, func(key.EndpointID) bool { return true }); err != nil {
		t.Fatal(err)
	}
	if _, err := FetchGroupInfo(ctx, bob.ep, alice.addr(), []byte("real-group")); err != nil {
		t.Fatalf("positive: %v", err)
	}
	t.Log("PASS positive: a GroupInfo signed by the endpoint serving it, for the group asked for")

	// Control (a): the same GroupInfo, republished under a group id the
	// caller did not ask for. The directory keys by the info's own id,
	// so ask for the one it holds but pass a different id to the check.
	if _, err := FetchGroupInfo(ctx, bob.ep, alice.addr(), []byte("other-group")); err == nil {
		t.Error("control (a): a fetch for a group the directory does not hold succeeded")
	} else {
		t.Logf("PASS control (a): wrong group id -> %v", err)
	}

	// Control (b): a GroupInfo that bob's endpoint signed, served from
	// an endpoint that is not bob. An honest directory refuses to
	// publish one, and a hostile responder that serves one anyway is
	// caught by the caller. Only the signer is wrong.
	binfo := newGroupInfo(t, bob.sk, "decoy", 0)
	if err := alice.dir.PublishGroupInfo(binfo, func(key.EndpointID) bool { return true }); !errors.Is(err, ErrWrongEndpoint) {
		t.Errorf("control (b): alice's directory published bob's GroupInfo: err=%v", err)
	}
	h := newHostile(t, ctx, message(t, binfo))
	if _, err := FetchGroupInfo(ctx, bob.ep, h, []byte("decoy")); !errors.Is(err, ErrWrongEndpoint) {
		t.Errorf("control (b): a GroupInfo signed by another endpoint was accepted: err=%v", err)
	} else {
		t.Logf("PASS control (b): signer is not the server -> %v", err)
	}
}

// TestKeyPackagePolicy checks that the pool is spent only on callers
// the policy admits.
//
// Positive: with a policy set, a stranger cannot drain the pool.
// Negative control: with no policy - the documented default - the same
// stranger still can, so the policy is what is doing the work and the
// default is unchanged for existing callers.
func TestKeyPackagePolicy(t *testing.T) {
	if testing.Short() {
		t.Skip("network test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	for _, tt := range []struct {
		name   string
		policy func(key.EndpointID) bool
		want   int
	}{
		{"gated", func(key.EndpointID) bool { return false }, 0},
		{"control: no policy (default)", nil, 3},
	} {
		t.Run(tt.name, func(t *testing.T) {
			owner, stranger := newNode(t, ctx), newNode(t, ctx)
			owner.publish(t, 3)
			owner.dir.AdmitKeyPackages(tt.policy)
			got := 0
			for {
				if _, err := FetchKeyPackage(ctx, stranger.ep, owner.addr(), Suite); err != nil {
					break
				}
				got++
			}
			if got != tt.want {
				t.Errorf("stranger consumed %d key packages, want %d (pool left %d)", got, tt.want, owner.dir.Len())
			} else {
				t.Logf("stranger consumed %d, pool left %d", got, owner.dir.Len())
			}
		})
	}
}

// TestLargeWelcomeDelivers checks that a Welcome may use the size its
// own limit allows, and that no other operation gains from it.
//
// Positive: a Welcome for a group well past the old 64 KiB request
// ceiling is delivered and reaches the owner's stream.
// Negative control: a request past the operation's own limit is still
// refused, so the ceiling moved rather than vanished.
func TestLargeWelcomeDelivers(t *testing.T) {
	if testing.Short() {
		t.Skip("network test")
	}
	owner, sender := newNode(t, context.Background()), newNode(t, context.Background())
	kp, _ := newKeyPackage(t, owner.sk)
	if err := owner.dir.Add(kp); err != nil {
		t.Fatal(err)
	}

	// A group of several hundred, added in one commit, which puts the
	// Welcome past the old ceiling. It is built before the network
	// clock starts: under the race detector it is most of the test.
	const members = 300
	founder, err := NewClient(sender.sk, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	g, err := founder.NewGroup([]byte("big"), nil)
	if err != nil {
		t.Fatal(err)
	}
	adds := []*mls.Proposal{{Type: mls.ProposalTypeAdd, Add: &mls.Add{KeyPackage: *kp}}}
	for len(adds) < members-1 {
		sk, err := key.GenerateSecretKey()
		if err != nil {
			t.Fatal(err)
		}
		other, err := NewClient(sk, time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		adds = append(adds, &mls.Proposal{Type: mls.ProposalTypeAdd, Add: &mls.Add{KeyPackage: *other.KeyPackage}})
	}
	_, _, w, err := g.Commit(adds)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := mls.Marshal(w.Welcome)
	t.Logf("welcome for a %d-member group: %d bytes (old ceiling %d)", members, len(b), MaxRequestSize)
	if len(b) <= MaxRequestSize {
		t.Fatalf("test is not exercising the old ceiling: welcome is only %d bytes", len(b))
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	got := make(chan Welcome, 4)
	go func() {
		for w := range owner.dir.Welcomes() {
			got <- w
		}
	}()
	// A Welcome is routed only for a key package the directory
	// served, so the sender fetches the one it added.
	if _, err := FetchKeyPackage(ctx, sender.ep, owner.addr(), Suite); err != nil {
		t.Fatal(err)
	}
	if err := DeliverWelcome(ctx, sender.ep, owner.addr(), w.Welcome); err != nil {
		t.Fatalf("positive: %v", err)
	}
	select {
	case <-got:
		t.Log("PASS positive: the large Welcome reached the owner's stream")
	case <-time.After(5 * time.Second):
		t.Fatal("positive: the Welcome never reached the stream")
	}

	// Control: a fetch_key_package request is still held to the small
	// limit, so the larger bound did not leak to every operation.
	if opFetchKeyPackage.maxRequestSize() != MaxRequestSize {
		t.Errorf("control: fetch_key_package limit is %d, want %d", opFetchKeyPackage.maxRequestSize(), MaxRequestSize)
	} else {
		t.Logf("PASS control: fetch_key_package is still bounded at %d", MaxRequestSize)
	}
}

// hostile is a directory handler that answers every fetch_group_info
// with a GroupInfo of its own choosing, which is what a compromised or
// relaying member can do. It exists to exercise the group-id check that
// an honest Directory never reaches, because an honest Directory keys
// its groups by the id the caller asks for.
// A nil body stalls: the responder reads the request and never answers.
type hostile struct{ body []byte }

func (h hostile) Accept(ctx context.Context, conn *iroh.Conn) error {
	for {
		stream, err := conn.AcceptStream(ctx)
		if err != nil {
			return nil
		}
		go func() {
			defer stream.Close()
			_, _ = io.ReadAll(io.LimitReader(stream, MaxWelcomeSize+MaxRequestSize+1))
			if h.body == nil {
				<-ctx.Done()
				return
			}
			b, err := mls.Marshal(&response{Version: version, Status: StatusOK, Body: h.body})
			if err != nil {
				return
			}
			_, _ = stream.Write(b)
			_ = stream.CloseWrite()
		}()
	}
}

// newHostile starts a hostile responder answering body on an endpoint
// of its own and returns that endpoint's address.
func newHostile(t *testing.T, ctx context.Context, body []byte) netaddr.EndpointAddr {
	t.Helper()
	ep, err := iroh.Bind(ctx, iroh.WithBindAddr(netip.AddrPortFrom(netip.IPv6Loopback(), 0)))
	if err != nil {
		t.Fatal(err)
	}
	router, err := iroh.NewRouter(ep, map[string]iroh.ProtocolHandler{ALPN: hostile{body}}, nil)
	if err != nil {
		ep.Shutdown(ctx)
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		router.Shutdown(ctx)
		ep.Shutdown(ctx)
	})
	return ep.Addr()
}

// message encodes v as the body of an MLSMessage.
func message(t *testing.T, v any) []byte {
	t.Helper()
	m := &mls.Message{Version: mls.Version10}
	switch v := v.(type) {
	case *mls.GroupInfo:
		m.WireFormat, m.GroupInfo = mls.WireFormatGroupInfo, v
	case *mls.KeyPackage:
		m.WireFormat, m.KeyPackage = mls.WireFormatKeyPackage, v
	default:
		t.Fatalf("message of %T", v)
	}
	b, err := mls.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestKeyPackageRateLimit checks the bound that applies when nobody
// installed a policy, which is the endpoint most likely to be drained.
//
// Positive: a stranger drawing hard is cut off after the rate and the
// pool keeps what is left.
// Negative control: the same stranger, under a rate raised past the pool
// size, empties it - so the limit and not the pool's own size is what
// stopped it.
func TestKeyPackageRateLimit(t *testing.T) {
	if testing.Short() {
		t.Skip("network test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	const pool = defaultKeyPackageRate + 4
	drain := func(t *testing.T, rate int) (got, left int) {
		t.Helper()
		owner := newNode(t, ctx)
		stranger := newNode(t, ctx)
		owner.dir.LimitKeyPackages(rate, 0, time.Minute)
		// More key packages than the default rate allows, so the
		// rate is what stops the stranger rather than the pool
		// running out.
		owner.publish(t, pool)
		for i := 0; i < pool; i++ {
			if _, err := FetchKeyPackage(ctx, stranger.ep, owner.addr(), Suite); err != nil {
				break
			}
			got++
		}
		return got, owner.dir.Len()
	}

	t.Run("default rate", func(t *testing.T) {
		got, left := drain(t, 0)
		t.Logf("stranger took %d of %d, pool left %d", got, pool, left)
		if got > defaultKeyPackageRate {
			t.Errorf("stranger took %d, over the rate of %d", got, defaultKeyPackageRate)
		}
		if left == 0 {
			t.Errorf("the whole pool went to one endpoint")
		}
	})
	t.Run("control: rate above the pool", func(t *testing.T) {
		got, left := drain(t, 100)
		t.Logf("stranger took %d of %d, pool left %d", got, pool, left)
		if got != pool || left != 0 {
			t.Errorf("control took %d leaving %d, want the whole pool; the rate is not the decisive predicate", got, left)
		}
	})
}

// TestGroupInfoWrongGroupID exercises the case an honest directory
// cannot produce, because it keys groups by the id it was asked for: a
// responder that answers a request for one group with a valid, correctly
// signed GroupInfo for another.
func TestGroupInfoWrongGroupID(t *testing.T) {
	if testing.Short() {
		t.Skip("network test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	sk, err := key.GenerateSecretKey()
	if err != nil {
		t.Fatal(err)
	}
	ep, err := iroh.Bind(ctx, iroh.WithSecretKey(sk), iroh.WithBindAddr(netip.AddrPortFrom(netip.IPv6Loopback(), 0)))
	if err != nil {
		t.Fatal(err)
	}
	defer ep.Shutdown(context.Background())

	c, err := NewClient(sk, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	g, err := c.NewGroup([]byte("the-group-it-really-is"), nil)
	if err != nil {
		t.Fatal(err)
	}
	info, err := g.GroupInfo()
	if err != nil {
		t.Fatal(err)
	}
	body, err := mls.Marshal(info)
	if err != nil {
		t.Fatal(err)
	}
	router, err := iroh.NewRouter(ep, map[string]iroh.ProtocolHandler{ALPN: hostile{body}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer router.Shutdown(context.Background())

	caller := newNode(t, ctx)
	addr := ep.Addr()

	// Positive: asked for what it serves, signed by the serving
	// endpoint. Accepted.
	if _, err := FetchGroupInfo(ctx, caller.ep, addr, []byte("the-group-it-really-is")); err != nil {
		t.Errorf("positive: %v", err)
	} else {
		t.Log("PASS positive: the hostile responder's own group, asked for by name, is accepted")
	}

	// Control: exactly one predicate differs - the group asked for.
	_, err = FetchGroupInfo(ctx, caller.ep, addr, []byte("the-group-i-asked-for"))
	if !errors.Is(err, ErrWrongGroup) {
		t.Errorf("control: a GroupInfo for another group was accepted: err=%v", err)
	} else {
		t.Logf("PASS control: wrong group id -> %v", err)
	}
}

// TestGroupInfoTampered checks that a caller verifies the GroupInfo
// signature itself: a GroupInfo whose signed content was changed after
// signing still names the right group and the right signer, and only
// the signature is wrong.
func TestGroupInfoTampered(t *testing.T) {
	if testing.Short() {
		t.Skip("network test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	sk, err := key.GenerateSecretKey()
	if err != nil {
		t.Fatal(err)
	}
	ep, err := iroh.Bind(ctx, iroh.WithSecretKey(sk), iroh.WithBindAddr(netip.AddrPortFrom(netip.IPv6Loopback(), 0)))
	if err != nil {
		t.Fatal(err)
	}
	defer ep.Shutdown(context.Background())
	info := newGroupInfo(t, sk, "g", 0)
	info.ConfirmationTag = append([]byte(nil), info.ConfirmationTag...)
	info.ConfirmationTag[0] ^= 1
	router, err := iroh.NewRouter(ep, map[string]iroh.ProtocolHandler{ALPN: hostile{message(t, info)}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer router.Shutdown(context.Background())

	caller := newNode(t, ctx)
	if _, err := FetchGroupInfo(ctx, caller.ep, ep.Addr(), []byte("g")); !errors.Is(err, ErrInvalidGroupInfo) {
		t.Fatalf("a tampered GroupInfo = %v, want ErrInvalidGroupInfo", err)
	}
}

// TestFetchKeyPackageWrongEndpoint checks that a responder cannot hand
// back a valid key package bound to some other endpoint.
func TestFetchKeyPackageWrongEndpoint(t *testing.T) {
	if testing.Short() {
		t.Skip("network test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	other, err := key.GenerateSecretKey()
	if err != nil {
		t.Fatal(err)
	}
	kp, _ := newKeyPackage(t, other)
	h := newHostile(t, ctx, message(t, kp))
	caller := newNode(t, ctx)
	if _, err := FetchKeyPackage(ctx, caller.ep, h, Suite); !errors.Is(err, ErrWrongEndpoint) {
		t.Fatalf("a key package bound to another endpoint = %v, want ErrWrongEndpoint", err)
	}
}

// TestRoundTripCanceled checks that canceling a context with no
// deadline stops a request that the responder never answers.
func TestRoundTripCanceled(t *testing.T) {
	if testing.Short() {
		t.Skip("network test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	h := newHostile(t, ctx, nil)
	caller := newNode(t, ctx)

	req, stop := context.WithCancel(context.Background())
	time.AfterFunc(500*time.Millisecond, stop)
	start := time.Now()
	_, err := FetchKeyPackage(req, caller.ep, h, Suite)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("FetchKeyPackage on a canceled context = %v, want context.Canceled", err)
	}
	if d := time.Since(start); d > readTimeout/2 {
		t.Fatalf("cancellation took %v", d)
	}
}

// openStream opens a raw delivery service stream to addr.
func openStream(t *testing.T, ctx context.Context, ep *iroh.Endpoint, addr netaddr.EndpointAddr) *iroh.Stream {
	t.Helper()
	conn, err := ep.Connect(ctx, addr, ALPN)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := stream.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatal(err)
	}
	return stream
}

// readStatus reads a response from stream and returns its status.
func readStatus(t *testing.T, stream *iroh.Stream) Status {
	t.Helper()
	b, err := io.ReadAll(stream)
	if err != nil {
		t.Fatalf("reading the response: %v", err)
	}
	var resp response
	if err := mls.Unmarshal(b, &resp); err != nil {
		t.Fatalf("decoding the response %x: %v", b, err)
	}
	return resp.Status
}

// TestWireStatuses checks the statuses a directory answers for
// requests the client in this package never sends.
func TestWireStatuses(t *testing.T) {
	if testing.Short() {
		t.Skip("network test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	alice, bob := newNode(t, ctx), newNode(t, ctx)

	enc := func(r request) []byte {
		b, err := mls.Marshal(&r)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	fetch := fetchBody(t)
	for _, tt := range []struct {
		name string
		req  []byte
		want Status
	}{
		{"unknown version", enc(request{Version: version + 1, Op: opFetchKeyPackage, Body: fetch}), StatusUnsupported},
		{"unknown op", enc(request{Version: version, Op: op(200), Body: fetch}), StatusUnsupported},
		{"oversize", enc(request{Version: version, Op: opFetchGroupInfo, Body: make([]byte, MaxRequestSize)}), StatusMalformed},
		{"truncated header", enc(request{Version: version, Op: opFetchKeyPackage})[:2], StatusMalformed},
		{"truncated body", enc(request{Version: version, Op: opFetchKeyPackage, Body: fetch})[:4], StatusMalformed},
		{"bad body", enc(request{Version: version, Op: opFetchKeyPackage, Body: []byte{1}}), StatusMalformed},
	} {
		t.Run(tt.name, func(t *testing.T) {
			s := openStream(t, ctx, alice.ep, bob.addr())
			if _, err := s.Write(tt.req); err != nil {
				t.Fatal(err)
			}
			if err := s.CloseWrite(); err != nil {
				t.Fatal(err)
			}
			if got := readStatus(t, s); got != tt.want {
				t.Fatalf("status = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestReadBoundedByOp checks that a directory reads no more of a
// request than its operation allows before answering. The request here
// is over its limit and never half-closed; a directory that read to
// the largest limit of any operation before looking at the op would
// hold the stream, and MaxWelcomeSize of memory, until the deadline.
func TestReadBoundedByOp(t *testing.T) {
	if testing.Short() {
		t.Skip("network test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	alice, bob := newNode(t, ctx), newNode(t, ctx)

	s := openStream(t, ctx, alice.ep, bob.addr())
	if _, err := s.Write([]byte{0, version, byte(opFetchKeyPackage)}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Write(make([]byte, 2*MaxRequestSize)); err != nil {
		t.Fatal(err)
	}
	if got := readStatus(t, s); got != StatusMalformed {
		t.Fatalf("status = %v, want malformed", got)
	}
}

// TestLargeReadsBounded checks that a directory reads only a bounded
// number of deliver_welcome requests, which may each be megabytes, at
// once: past the bound, a request waits for a slot before it is read.
func TestLargeReadsBounded(t *testing.T) {
	if testing.Short() {
		t.Skip("network test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	alice, bob := newNode(t, ctx), newNode(t, ctx)

	for range maxLargeReads {
		bob.dir.large <- struct{}{}
	}
	req, err := mls.Marshal(&request{Version: version, Op: opDeliverWelcome, Body: welcomeBody(t, testEntry(1).Ref)})
	if err != nil {
		t.Fatal(err)
	}
	s := openStream(t, ctx, alice.ep, bob.addr())
	if _, err := s.Write(req); err != nil {
		t.Fatal(err)
	}
	if err := s.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	status := make(chan Status, 1)
	go func() { status <- readStatus(t, s) }()
	select {
	case got := <-status:
		t.Fatalf("answered %v with every slot taken", got)
	case <-time.After(500 * time.Millisecond):
	}
	<-bob.dir.large
	if got := <-status; got != StatusNotFound {
		t.Fatalf("status once a slot was free = %v, want not_found", got)
	}
}

// TestNetworkClose checks that a closed directory stops serving, and
// that Close does not wait out a request still being read.
func TestNetworkClose(t *testing.T) {
	if testing.Short() {
		t.Skip("network test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	alice, bob := newNode(t, ctx), newNode(t, ctx)
	bob.publish(t, 1)

	// A request that has sent its header and nothing more.
	s := openStream(t, ctx, alice.ep, bob.addr())
	if _, err := s.Write([]byte{0, version, byte(opFetchKeyPackage)}); err != nil {
		t.Fatal(err)
	}
	time.Sleep(200 * time.Millisecond)

	start := time.Now()
	bob.dir.Close()
	if d := time.Since(start); d > readTimeout/2 {
		t.Fatalf("Close took %v", d)
	}
	if got := readStatus(t, s); got != StatusUnavailable {
		t.Fatalf("a request cut off by Close = %v, want unavailable", got)
	}
	if _, err := FetchKeyPackage(ctx, alice.ep, bob.addr(), Suite); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("fetch from a closed directory = %v, want unavailable", err)
	}
	if bob.dir.Len() != 1 {
		t.Fatal("a closed directory spent a key package")
	}
}

// TestPublishGroupInfoChecks checks what a directory refuses to publish,
// and that withdrawing one epoch leaves a later one published.
func TestPublishGroupInfoChecks(t *testing.T) {
	d := newTestDirectory(t, nil)
	admit := func(key.EndpointID) bool { return true }
	fetch := func(id string) Status {
		b, err := mls.Marshal(&fetchGroupInfoBody{GroupID: []byte(id)})
		if err != nil {
			t.Fatal(err)
		}
		status, _ := d.fetchGroupInfo(newEndpointID(t), b)
		return status
	}

	other, err := key.GenerateSecretKey()
	if err != nil {
		t.Fatal(err)
	}
	if err := d.PublishGroupInfo(newGroupInfo(t, other, "g", 0), admit); !errors.Is(err, ErrWrongEndpoint) {
		t.Fatalf("publishing another endpoint's GroupInfo = %v, want ErrWrongEndpoint", err)
	}
	forged := newGroupInfo(t, d.sk, "g", 0)
	forged.Signature = append([]byte(nil), forged.Signature...)
	forged.Signature[0] ^= 1
	if err := d.PublishGroupInfo(forged, admit); !errors.Is(err, ErrInvalidGroupInfo) {
		t.Fatalf("publishing a GroupInfo with a bad signature = %v, want ErrInvalidGroupInfo", err)
	}
	if err := d.PublishGroupInfo(nil, admit); err == nil {
		t.Fatal("published a nil GroupInfo")
	}

	c, err := NewClient(d.sk, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	g0, err := c.NewGroup([]byte("g"), nil)
	if err != nil {
		t.Fatal(err)
	}
	g1, _, _, err := g0.Commit(nil)
	if err != nil {
		t.Fatal(err)
	}
	info0, err := g0.GroupInfo()
	if err != nil {
		t.Fatal(err)
	}
	info1, err := g1.GroupInfo()
	if err != nil {
		t.Fatal(err)
	}
	if err := d.PublishGroupInfo(info1.GroupInfo, admit); err != nil {
		t.Fatal(err)
	}
	if err := d.PublishGroupInfo(info0.GroupInfo, admit); err == nil {
		t.Fatal("published epoch 0 over epoch 1")
	}
	d.WithdrawGroupInfo([]byte("g"), 0)
	if got := fetch("g"); got != StatusOK {
		t.Fatalf("after withdrawing epoch 0, epoch 1 = %v, want ok", got)
	}
	d.WithdrawGroupInfo([]byte("g"), 1)
	if got := fetch("g"); got != StatusNotFound {
		t.Fatalf("after withdrawing epoch 1 = %v, want not_found", got)
	}
}
