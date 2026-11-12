package mlsiroh

import (
	"errors"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tmc/go-iroh/key"
	"github.com/tmc/mls"
)

func newTestDirectory(t *testing.T, j Journal) *Directory {
	t.Helper()
	sk, err := key.GenerateSecretKey()
	if err != nil {
		t.Fatal(err)
	}
	d := NewDirectory(sk, j)
	t.Cleanup(func() { d.Close() })
	return d
}

// TestDirectoryReaddConsumed checks that a key package the directory
// has served cannot be put back into the pool. The consume-once rule of
// RFC 9420, Section 10, is enforceable only because the owner is the
// sole authority over its own pool, so the journal has to be consulted
// on the way in as well as on the way out.
func TestDirectoryReaddConsumed(t *testing.T) {
	d := newTestDirectory(t, nil)
	kp, _ := newKeyPackage(t, d.sk)
	if err := d.Add(kp); err != nil {
		t.Fatal(err)
	}
	if _, found, err := d.take(Suite); !found || err != nil {
		t.Fatalf("take = %v, %v; want a key package", found, err)
	}
	if d.Len() != 0 {
		t.Fatalf("pool holds %d key packages after take", d.Len())
	}
	if err := d.Add(kp); !errors.Is(err, ErrConsumed) {
		t.Fatalf("re-adding a served key package = %v, want ErrConsumed", err)
	}
	if _, found, _ := d.take(Suite); found {
		t.Fatal("served the same key package twice")
	}
}

// TestDirectoryInitKeyServedOnce checks that consume-once holds for the
// init key, which is what it protects, and not only for the reference:
// re-signing a key package with a new lifetime changes its reference
// and keeps its init key.
func TestDirectoryInitKeyServedOnce(t *testing.T) {
	d := newTestDirectory(t, nil)
	kp, seed := newKeyPackage(t, d.sk)
	resign := func() *mls.KeyPackage {
		t.Helper()
		again := *kp
		again.LeafNode.Lifetime.NotAfter++
		if err := Sign(d.sk, seed, &again); err != nil {
			t.Fatal(err)
		}
		r1, _ := kp.Ref()
		r2, _ := again.Ref()
		if string(r1) == string(r2) {
			t.Fatal("re-signing did not change the reference; the test proves nothing")
		}
		return &again
	}

	// Both in the pool: the second replaces the first.
	if err := d.Add(kp); err != nil {
		t.Fatal(err)
	}
	if err := d.Add(resign()); err != nil {
		t.Fatal(err)
	}
	if n := d.Len(); n != 1 {
		t.Fatalf("pool holds %d key packages with one init key, want 1", n)
	}
	if _, found, err := d.take(Suite); !found || err != nil {
		t.Fatalf("take = %v, %v", found, err)
	}
	// Served once, neither the original nor a re-signing comes back.
	if err := d.Add(kp); !errors.Is(err, ErrConsumed) {
		t.Fatalf("Add of the original = %v, want ErrConsumed", err)
	}
	if err := d.Add(resign()); !errors.Is(err, ErrConsumed) {
		t.Fatalf("Add of a re-signing = %v, want ErrConsumed", err)
	}
}

// TestDirectoryTakeIsAtomic checks that a key package is not consumed
// when the journal refuses to record it: a directory that cannot make
// the consumption durable must serve nothing rather than serve
// something it cannot remember serving. The caller is told to retry.
func TestDirectoryTakeIsAtomic(t *testing.T) {
	d := newTestDirectory(t, failJournal{})
	kp, _ := newKeyPackage(t, d.sk)
	if err := d.Add(kp); err != nil {
		t.Fatal(err)
	}
	if status, _ := d.fetchKeyPackage(newEndpointID(t), fetchBody(t)); status != StatusUnavailable {
		t.Fatalf("fetch with an unwritable journal = %v, want unavailable", status)
	}
	if d.Len() != 1 {
		t.Fatalf("pool holds %d key packages, want the unrecorded one back", d.Len())
	}
}

// failJournal records nothing and says so.
type failJournal struct{}

var errNoJournal = errors.New("journal is unwritable")

func (failJournal) Record(Entry) error           { return errNoJournal }
func (failJournal) Consumed(Entry) (bool, error) { return false, nil }
func (failJournal) Lookup(mls.HashReference) (Entry, bool, error) {
	return Entry{}, false, errNoJournal
}

func fetchBody(t *testing.T) []byte {
	t.Helper()
	b, err := mls.Marshal(&fetchKeyPackageBody{CipherSuite: Suite})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// welcomeBody returns a deliver_welcome body naming refs.
func welcomeBody(t *testing.T, refs ...mls.HashReference) []byte {
	t.Helper()
	w := &mls.Welcome{CipherSuite: Suite}
	for _, ref := range refs {
		w.Secrets = append(w.Secrets, mls.EncryptedGroupSecrets{NewMember: ref})
	}
	b, err := mls.Marshal(&mls.Message{Version: mls.Version10, WireFormat: mls.WireFormatWelcome, Welcome: w})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// served records n synthetic served key packages in d's journal and
// returns their references.
func served(t *testing.T, d *Directory, n int) []mls.HashReference {
	t.Helper()
	var refs []mls.HashReference
	for i := range n {
		e := testEntry(i)
		e.NotAfter = uint64(time.Now().Add(time.Hour).Unix())
		if err := d.journal.Record(e); err != nil {
			t.Fatal(err)
		}
		refs = append(refs, e.Ref)
	}
	return refs
}

// TestDirectoryCloseDrainsWelcomes checks that closing a directory does
// not discard Welcomes it has already accepted. deliverWelcome answers
// ok once the Welcome is queued, and a sender that hears ok must not
// have to wonder whether the joiner got it.
func TestDirectoryCloseDrainsWelcomes(t *testing.T) {
	d := newTestDirectory(t, nil)
	refs := served(t, d, 4)
	for i, ref := range refs {
		from := newEndpointID(t)
		if status, _ := d.deliverWelcome(from, welcomeBody(t, ref)); status != StatusOK {
			t.Fatalf("welcome %d = %v", i, status)
		}
	}
	d.Close()

	got := 0
	for range d.Welcomes() {
		got++
	}
	if got != len(refs) {
		t.Fatalf("drained %d welcomes after close, want %d", got, len(refs))
	}
}

// TestDirectoryClosedServesNothing checks that a closed directory
// answers every operation unavailable rather than serving from a pool
// or queue that nobody is running any more.
func TestDirectoryClosedServesNothing(t *testing.T) {
	d := newTestDirectory(t, nil)
	kp, _ := newKeyPackage(t, d.sk)
	if err := d.Add(kp); err != nil {
		t.Fatal(err)
	}
	refs := served(t, d, 1)
	d.Close()
	for _, req := range []request{
		{Op: opFetchKeyPackage, Body: fetchBody(t)},
		{Op: opDeliverWelcome, Body: welcomeBody(t, refs...)},
		{Op: opFetchGroupInfo, Body: []byte{0}},
	} {
		if status, _ := d.dispatch(d.id, &req); status != StatusUnavailable {
			t.Errorf("%v on a closed directory = %v, want unavailable", req.Op, status)
		}
	}
	if d.Len() != 1 {
		t.Error("a closed directory spent a key package")
	}
}

// TestDirectoryPolicyPanics checks that a policy that panics refuses
// the request rather than crashing the process that serves it.
func TestDirectoryPolicyPanics(t *testing.T) {
	d := newTestDirectory(t, nil)
	kp, _ := newKeyPackage(t, d.sk)
	if err := d.Add(kp); err != nil {
		t.Fatal(err)
	}
	d.AdmitKeyPackages(func(key.EndpointID) bool { panic("policy bug") })
	req := request{Op: opFetchKeyPackage, Body: fetchBody(t)}
	if status, _ := d.dispatch(newEndpointID(t), &req); status != StatusUnavailable {
		t.Fatalf("fetch under a panicking policy = %v, want unavailable", status)
	}
	if d.Len() != 1 {
		t.Fatal("a panicking policy spent a key package")
	}
}

// TestDirectoryExpired checks that an expired key package is dropped
// rather than served: serving it would spend it on a joiner whose
// client has to refuse it.
func TestDirectoryExpired(t *testing.T) {
	d := newTestDirectory(t, nil)
	kp, seed := newKeyPackage(t, d.sk)
	kp.LeafNode.Lifetime.NotAfter = uint64(time.Now().Add(-time.Minute).Unix())
	if err := Sign(d.sk, seed, kp); err != nil {
		t.Fatal(err)
	}
	// Add refuses an expired key package, so put it in the pool as
	// if it had expired there.
	d.mu.Lock()
	d.pool[string(kp.InitKey)] = kp
	d.mu.Unlock()

	if status, _ := d.fetchKeyPackage(newEndpointID(t), fetchBody(t)); status != StatusExhausted {
		t.Fatalf("fetch from a pool of one expired key package = %v, want exhausted", status)
	}
	if n := d.Len(); n != 0 {
		t.Fatalf("pool holds %d key packages, want the expired one dropped", n)
	}
	e, _ := entry(kp)
	if ok, _ := d.journal.Consumed(e); ok {
		t.Fatal("the expired key package was journaled as served")
	}

	// Len alone prunes too.
	d.mu.Lock()
	d.pool[string(kp.InitKey)] = kp
	d.mu.Unlock()
	if n := d.Len(); n != 0 {
		t.Fatalf("Len = %d, counting an expired key package", n)
	}
}

// TestDirectoryWelcomeAfterRestart checks that a Welcome for a key
// package served before a restart is still routed after it. The
// journal records the key package, and Add refuses to put it back, so
// if the journal did not route the Welcome nothing would.
func TestDirectoryWelcomeAfterRestart(t *testing.T) {
	name := filepath.Join(t.TempDir(), "journal")
	j, err := OpenJournal(name)
	if err != nil {
		t.Fatal(err)
	}
	d := newTestDirectory(t, j)
	kp, _ := newKeyPackage(t, d.sk)
	if err := d.Add(kp); err != nil {
		t.Fatal(err)
	}
	if _, found, err := d.take(Suite); !found || err != nil {
		t.Fatalf("take = %v, %v", found, err)
	}
	d.Close()
	j.Close()

	j, err = OpenJournal(name)
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	d = NewDirectory(d.sk, j)
	defer d.Close()
	if err := d.Add(kp); !errors.Is(err, ErrConsumed) {
		t.Fatalf("Add after restart = %v, want ErrConsumed", err)
	}
	ref, _ := kp.Ref()
	if status, _ := d.deliverWelcome(newEndpointID(t), welcomeBody(t, ref)); status != StatusOK {
		t.Fatalf("Welcome for a key package served before the restart = %v, want ok", status)
	}

	// Control: a reference the journal does not hold is not routed.
	if status, _ := d.deliverWelcome(newEndpointID(t), welcomeBody(t, testEntry(1).Ref)); status != StatusNotFound {
		t.Fatalf("Welcome for an unknown key package = %v, want not_found", status)
	}
}

// TestDirectoryWelcomeBounds checks the bounds on deliver_welcome that
// keep a caller who holds one served reference - anyone who fetched a
// key package - from filling the queue for everyone.
func TestDirectoryWelcomeBounds(t *testing.T) {
	t.Run("per key package", func(t *testing.T) {
		d := newTestDirectory(t, nil)
		ref := served(t, d, 1)[0]
		for i := range maxWelcomesPerKeyPackage {
			if status, _ := d.deliverWelcome(newEndpointID(t), welcomeBody(t, ref)); status != StatusOK {
				t.Fatalf("welcome %d = %v, want ok", i, status)
			}
		}
		if status, _ := d.deliverWelcome(newEndpointID(t), welcomeBody(t, ref)); status != StatusExhausted {
			t.Fatalf("welcome past the bound for one key package = %v, want exhausted", status)
		}
	})
	t.Run("per sender queue", func(t *testing.T) {
		d := newTestDirectory(t, nil)
		refs := served(t, d, maxQueuedPerSender+1)
		from := newEndpointID(t)
		for i, ref := range refs[:maxQueuedPerSender] {
			if status, _ := d.deliverWelcome(from, welcomeBody(t, ref)); status != StatusOK {
				t.Fatalf("welcome %d = %v, want ok", i, status)
			}
		}
		last := welcomeBody(t, refs[maxQueuedPerSender])
		if status, _ := d.deliverWelcome(from, last); status != StatusUnavailable {
			t.Fatalf("welcome past the sender's share = %v, want unavailable", status)
		}
		// Another sender still has its share.
		if status, _ := d.deliverWelcome(newEndpointID(t), last); status != StatusOK {
			t.Fatalf("another sender's welcome = %v, want ok", status)
		}
		// Draining one gives the share back.
		for range d.Welcomes() {
			break
		}
		if status, _ := d.deliverWelcome(from, welcomeBody(t, refs[0])); status != StatusOK {
			t.Fatalf("welcome after a drain = %v, want ok", status)
		}
	})
	t.Run("full queue", func(t *testing.T) {
		d := newTestDirectory(t, nil)
		refs := served(t, d, welcomeQueue)
		for i, ref := range refs {
			if status, _ := d.deliverWelcome(newEndpointID(t), welcomeBody(t, ref)); status != StatusOK {
				t.Fatalf("welcome %d = %v, want ok", i, status)
			}
		}
		if status, _ := d.deliverWelcome(newEndpointID(t), welcomeBody(t, refs[0])); status != StatusUnavailable {
			t.Fatalf("welcome to a full queue = %v, want unavailable", status)
		}
	})
	t.Run("per sender rate", func(t *testing.T) {
		d := newTestDirectory(t, nil)
		from := newEndpointID(t)
		probe := welcomeBody(t, testEntry(1).Ref)
		for i := range defaultWelcomeRate {
			if status, _ := d.deliverWelcome(from, probe); status != StatusNotFound {
				t.Fatalf("probe %d = %v, want not_found", i, status)
			}
		}
		if status, _ := d.deliverWelcome(from, probe); status != StatusExhausted {
			t.Fatalf("probe past the rate = %v, want exhausted", status)
		}
	})
	t.Run("total rate", func(t *testing.T) {
		d := newTestDirectory(t, nil)
		probe := welcomeBody(t, testEntry(1).Ref)
		for i := range defaultWelcomeTotal {
			if status, _ := d.deliverWelcome(newEndpointID(t), probe); status != StatusNotFound {
				t.Fatalf("probe %d = %v, want not_found", i, status)
			}
		}
		if status, _ := d.deliverWelcome(newEndpointID(t), probe); status != StatusExhausted {
			t.Fatalf("a fresh endpoint past the total = %v, want exhausted", status)
		}
	})
	t.Run("journal failure", func(t *testing.T) {
		d := newTestDirectory(t, failJournal{})
		if status, _ := d.deliverWelcome(newEndpointID(t), welcomeBody(t, testEntry(1).Ref)); status != StatusUnavailable {
			t.Fatalf("welcome with an unreadable journal = %v, want unavailable", status)
		}
	})
}

// TestLimiter checks that the bookkeeping stays bounded under many
// endpoint ids, which cost an attacker nothing, and that the total is
// what then bounds them.
func TestLimiter(t *testing.T) {
	now := time.Now()
	id := func(i int) key.EndpointID {
		var b [32]byte
		b[0], b[1], b[2] = byte(i), byte(i>>8), byte(i>>16)
		return key.UncheckedEndpointID(b)
	}

	t.Run("bounded", func(t *testing.T) {
		l := newLimiter(1, -1, time.Minute)
		start := time.Now()
		for i := range 5 * maxCallers {
			l.allowCaller(id(i), now)
		}
		if n := len(l.callers); n > maxCallers {
			t.Fatalf("limiter tracks %d callers, want at most %d", n, maxCallers)
		}
		if d := time.Since(start); d > 5*time.Second {
			t.Fatalf("%d calls took %v", 5*maxCallers, d)
		}
	})
	t.Run("total", func(t *testing.T) {
		l := newLimiter(1, 3, time.Minute)
		got := 0
		for i := range 10 {
			if l.allowCaller(id(i), now) && l.allowTotal(now) {
				got++
			}
		}
		if got != 3 {
			t.Fatalf("10 endpoints got %d, want the total of 3", got)
		}
	})
	t.Run("window", func(t *testing.T) {
		l := newLimiter(2, -1, time.Minute)
		for range 2 {
			if !l.allowCaller(id(0), now) {
				t.Fatal("refused inside the rate")
			}
		}
		if l.allowCaller(id(0), now) {
			t.Fatal("allowed past the rate")
		}
		if !l.allowCaller(id(0), now.Add(time.Minute)) {
			t.Fatal("refused in a new window")
		}
	})
	t.Run("unlimited", func(t *testing.T) {
		l := newLimiter(-1, -1, time.Minute)
		for range 100 {
			if !l.allowCaller(id(0), now) || !l.allowTotal(now) {
				t.Fatal("a negative bound refused")
			}
		}
	})
}

// TestLimitKeyPackages checks the knobs: a negative rate removes the
// bound, zero restores the default, and the window resets the count.
func TestLimitKeyPackages(t *testing.T) {
	d := newTestDirectory(t, nil)
	from := newEndpointID(t)
	fetches := func(n int) (got int) {
		for range n {
			if status, _ := d.fetchKeyPackage(from, fetchBody(t)); status != StatusExhausted {
				t.Fatalf("fetch from an empty pool = %v", status)
			}
			d.mu.Lock()
			got = d.fetches.callers[from]
			d.mu.Unlock()
		}
		return got
	}
	// With the pool empty every fetch answers exhausted either way,
	// so what the limiter counted is the observable.
	d.LimitKeyPackages(-1, 0, 0)
	if got := fetches(20); got != 0 {
		t.Fatalf("a negative rate still counted %d fetches", got)
	}
	d.LimitKeyPackages(0, 0, 0)
	if got := fetches(20); got != defaultKeyPackageRate {
		t.Fatalf("the default rate counted %d fetches, want %d", got, defaultKeyPackageRate)
	}
	d.LimitKeyPackages(2, 0, 10*time.Millisecond)
	fetches(2)
	time.Sleep(20 * time.Millisecond)
	if got := fetches(1); got != 1 {
		t.Fatalf("after the window, the count is %d, want 1", got)
	}
}

// TestPublishOncePolicy checks the one-fetch policy the
// PublishGroupInfo documentation shows: a stranger's probe must not
// spend the joiner's fetch.
func TestPublishOncePolicy(t *testing.T) {
	joiner, stranger := newEndpointID(t), newEndpointID(t)
	var used atomic.Bool
	policy := func(id key.EndpointID) bool {
		return id.Equal(joiner) && used.CompareAndSwap(false, true)
	}
	if policy(stranger) {
		t.Fatal("admitted a stranger")
	}
	if !policy(joiner) {
		t.Fatal("a stranger's probe locked out the joiner")
	}
	if policy(joiner) {
		t.Fatal("admitted the joiner twice")
	}
}

// TestDirectoryConsumedAcrossRestart checks consume-once across a
// restart on a FileJournal: neither a served key package nor a
// re-signing of it is served by the next run, and one that was in the
// pool and never served still is.
func TestDirectoryConsumedAcrossRestart(t *testing.T) {
	name := filepath.Join(t.TempDir(), "journal")
	sk, err := key.GenerateSecretKey()
	if err != nil {
		t.Fatal(err)
	}
	j, err := OpenJournal(name)
	if err != nil {
		t.Fatal(err)
	}
	d := NewDirectory(sk, j)
	served, seed := newKeyPackage(t, sk)
	if err := d.Add(served); err != nil {
		t.Fatal(err)
	}
	if _, found, err := d.take(Suite); !found || err != nil {
		t.Fatalf("take = %v, %v; want a key package", found, err)
	}
	unserved, _ := newKeyPackage(t, sk)
	if err := d.Add(unserved); err != nil {
		t.Fatal(err)
	}
	d.Close()
	j.Close()

	j, err = OpenJournal(name)
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	d = NewDirectory(sk, j)
	defer d.Close()
	resigned := *served
	resigned.LeafNode.Lifetime.NotAfter++
	if err := Sign(sk, seed, &resigned); err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct {
		name string
		kp   *mls.KeyPackage
		want error
	}{
		{"served", served, ErrConsumed},
		{"re-signed", &resigned, ErrConsumed},
		{"never served", unserved, nil},
	} {
		if err := d.Add(tt.kp); !errors.Is(err, tt.want) {
			t.Errorf("Add of the %s key package after restart = %v, want %v", tt.name, err, tt.want)
		}
	}
	if n := d.Len(); n != 1 {
		t.Fatalf("pool holds %d after restart, want 1", n)
	}
}
