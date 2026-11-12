package mlsiroh

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"iter"
	"sync"
	"time"

	"github.com/tmc/go-iroh/iroh"
	"github.com/tmc/go-iroh/key"
	"github.com/tmc/mls"
)

// readTimeout bounds how long a handler waits for a request. Half-close
// delimits a message, so without a deadline a peer that sends an opcode
// and never finishes holds the stream forever.
const readTimeout = 30 * time.Second

// A Welcome is a Welcome message and the endpoint that delivered it.
type Welcome struct {
	From    key.EndpointID
	Message *mls.Welcome
}

// A Directory serves one endpoint's key packages, accepts Welcomes
// addressed to them, and serves the GroupInfo of groups it publishes.
//
// It is the whole of the MLS delivery service for one member. There is
// no shared directory: a client serves its own key packages, which is
// what makes the consume-once rule of RFC 9420, Section 10, enforceable
// — the owner is the only authority over its own pool.
//
// Its methods are safe for concurrent use. The zero Directory is not
// usable; call [NewDirectory].
type Directory struct {
	sk      key.SecretKey
	id      key.EndpointID
	journal Journal

	// ctx is canceled by Close. Every handler checks it.
	ctx    context.Context
	cancel context.CancelFunc

	mu         sync.Mutex
	poolPolicy func(key.EndpointID) bool
	fetches    limiter                    // fetch_key_package
	deliveries limiter                    // deliver_welcome
	pool       map[string]*mls.KeyPackage // by init key, unserved only
	delivered  map[string]delivered       // by key package reference
	queued     map[key.EndpointID]int     // Welcomes in the queue, by sender
	groups     map[string]*group

	welcomes chan Welcome
	large    chan struct{} // held while a large request is read

	closemu sync.Mutex
	closed  bool
	streams sync.WaitGroup
}

// A group is a published GroupInfo and the policy that gates it.
type group struct {
	epoch  uint64
	msg    []byte // the GroupInfo as an MLSMessage, encoded at publish
	policy func(key.EndpointID) bool
}

// delivered counts the Welcomes accepted for one served key package.
type delivered struct {
	n        int
	notAfter uint64
}

const (
	// welcomeQueue is how many Welcomes wait for [Directory.Welcomes].
	welcomeQueue = 16

	// maxQueuedPerSender is how much of the queue one sender may
	// hold, so that one endpoint cannot fill it for everyone.
	maxQueuedPerSender = 4

	// maxWelcomesPerKeyPackage is how many Welcomes naming one key
	// package are accepted. A Welcome is delivered once; the spare
	// is for a sender that did not hear the first ok.
	maxWelcomesPerKeyPackage = 3

	// maxLargeReads is how many deliver_welcome requests, which may
	// run to MaxWelcomeSize, a directory reads at once.
	maxLargeReads = 4
)

// NewDirectory returns a directory that serves key packages bound to
// sk's endpoint, recording served key packages in journal.
//
// A nil journal keeps that record in memory only, which re-serves
// consumed key packages after a restart; it is suitable only for tests.
// See [Journal] for why that matters and [OpenJournal] for the durable
// implementation.
func NewDirectory(sk key.SecretKey, journal Journal) *Directory {
	if journal == nil {
		journal = new(MemoryJournal)
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &Directory{
		sk:         sk,
		id:         sk.Public().EndpointID(),
		journal:    journal,
		ctx:        ctx,
		cancel:     cancel,
		fetches:    newLimiter(defaultKeyPackageRate, defaultKeyPackageTotal, defaultWindow),
		deliveries: newLimiter(defaultWelcomeRate, defaultWelcomeTotal, defaultWindow),
		pool:       make(map[string]*mls.KeyPackage),
		delivered:  make(map[string]delivered),
		queued:     make(map[key.EndpointID]int),
		groups:     make(map[string]*group),
		welcomes:   make(chan Welcome, welcomeQueue),
		large:      make(chan struct{}, maxLargeReads),
	}
}

// Add puts kp in the pool that fetch_key_package draws from. A key
// package already in the pool with the same init key is replaced, so
// re-signing one with a new lifetime does not put its init key in the
// pool twice.
//
// It reports an error unless kp carries the iroh:ed25519 binding for
// the directory's own endpoint and passes the leaf node rules of RFC
// 9420, Section 7.3. A key package whose reference or init key the
// journal records as served is refused with [ErrConsumed].
func (d *Directory) Add(kp *mls.KeyPackage) error {
	id, err := Verify(kp, time.Now())
	if err != nil {
		return err
	}
	if !id.Equal(d.id) {
		return fmt.Errorf("%w: key package names %v, serving %v", ErrWrongEndpoint, id, d.id)
	}
	e, err := entry(kp)
	if err != nil {
		return err
	}
	// Under the same lock that take holds, so that a key package
	// being served cannot be put back between its removal from the
	// pool and its record in the journal.
	d.mu.Lock()
	defer d.mu.Unlock()
	consumed, err := d.journal.Consumed(e)
	if err != nil {
		return fmt.Errorf("mlsiroh: reading journal: %w", err)
	}
	if consumed {
		return fmt.Errorf("%w: %x", ErrConsumed, []byte(e.Ref))
	}
	d.pool[string(kp.InitKey)] = kp
	d.forgetExpired(time.Now())
	return nil
}

const (
	// The defaults bound how fast callers can spend the pool and fill
	// the Welcome queue. They apply even with no policy installed,
	// because the endpoint most likely to be drained is the one that
	// never thought about it. A joiner needs one key package; a
	// handful per minute leaves room for retries and for a member
	// adding several people at once. The totals are what bound an
	// attacker with many endpoint ids, which cost nothing to make.
	defaultKeyPackageRate  = 8
	defaultKeyPackageTotal = 64
	defaultWelcomeRate     = 8
	defaultWelcomeTotal    = 64
	defaultWindow          = time.Minute

	// maxCallers bounds a limiter's bookkeeping. A caller past it is
	// not counted individually, only against the total.
	maxCallers = 4096
)

// A limiter bounds how often callers may do something: at most rate
// times per caller and total times across all callers in each window.
// A negative rate or total is no bound. The windows are fixed rather
// than sliding, so that starting a new one is forgetting everything,
// which costs nothing per call.
type limiter struct {
	rate, total int
	window      time.Duration
	start       time.Time
	n           int
	callers     map[key.EndpointID]int
}

func newLimiter(rate, total int, window time.Duration) limiter {
	return limiter{rate: rate, total: total, window: window, callers: make(map[key.EndpointID]int)}
}

func (l *limiter) roll(now time.Time) {
	if now.Sub(l.start) >= l.window || now.Before(l.start) {
		l.start = now
		l.n = 0
		clear(l.callers)
	}
}

// allowCaller reports whether from may act now, and counts it when it
// may.
func (l *limiter) allowCaller(from key.EndpointID, now time.Time) bool {
	l.roll(now)
	if l.rate < 0 {
		return true
	}
	n, ok := l.callers[from]
	if !ok && len(l.callers) >= maxCallers {
		return true
	}
	if n >= l.rate {
		return false
	}
	l.callers[from] = n + 1
	return true
}

// allowTotal reports whether anybody may act now, and counts it when
// they may.
func (l *limiter) allowTotal(now time.Time) bool {
	l.roll(now)
	if l.total < 0 {
		return true
	}
	if l.n >= l.total {
		return false
	}
	l.n++
	return true
}

// LimitKeyPackages sets how many key packages one endpoint may fetch
// per window, and how many all endpoints together may. Zero restores a
// default: 8 per endpoint and 64 in all per minute. A negative bound
// removes it, which is only sensible behind a policy that already knows
// its callers.
//
// The bound per endpoint is no defense against a caller with many
// endpoint ids, which cost nothing to make; the total is. It keeps the
// pool from being emptied faster than it bounds, at the price of
// letting such a caller spend everyone's share: an endpoint that must
// stay addable under that attack also needs [Directory.AdmitKeyPackages].
func (d *Directory) LimitKeyPackages(perEndpoint, total int, window time.Duration) {
	if perEndpoint == 0 {
		perEndpoint = defaultKeyPackageRate
	}
	if total == 0 {
		total = defaultKeyPackageTotal
	}
	if window <= 0 {
		window = defaultWindow
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	d.fetches = newLimiter(perEndpoint, total, window)
}

// AdmitKeyPackages sets the policy that gates fetch_key_package. A nil
// policy, the default, admits everyone, which is the normal arrangement:
// being addable to a group is not usually a secret.
//
// It is here because a fetch is not free. Each one consumes a key
// package durably, so an endpoint that publishes to an open pool can
// have it emptied and kept empty by anyone who can dial it, and joiners
// then get StatusExhausted. An endpoint that expects to be added only by
// people it already knows should say so. A caller the policy refuses
// is not counted against the total of [Directory.LimitKeyPackages].
//
// The policy is called concurrently, from the goroutine serving each
// request, and must be safe for that. A policy that panics refuses the
// request with StatusUnavailable.
func (d *Directory) AdmitKeyPackages(policy func(key.EndpointID) bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.poolPolicy = policy
}

// Len returns the number of unserved, unexpired key packages in the
// pool.
func (d *Directory) Len() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.forgetExpired(time.Now())
	return len(d.pool)
}

// PublishGroupInfo makes info available to callers that policy admits,
// for the group it names. A nil policy admits nobody, which is the
// default a group should have to override: a GroupInfo discloses the
// full membership roster, every member's credential, and the epoch
// (RFC 9420, Section 16.4.2), and its external_pub lets the caller
// mount an external commit.
//
// It reports an error unless info carries both the ratchet_tree and
// external_pub extensions, which an external joiner needs and which
// together are the only reason to serve a GroupInfo at all; unless it
// is signed by a leaf bound to this directory's endpoint, which is what
// [FetchGroupInfo] checks; and if a later epoch of the group is already
// published. The directory serves info as it was when published, so
// changing it afterwards changes nothing.
//
// A GroupInfo describes one epoch and an external join ends it, so
// each one admits a single joiner (RFC 9420, Section 12.4.3.2). After
// applying a join, publish the new epoch's GroupInfo to admit another.
// A GroupInfo left published past its epoch cannot produce a join —
// the group rejects the resulting commit — but it still discloses that
// epoch's roster to anyone the policy admits, so withdraw it.
//
// The policy is consulted on every fetch, not once per endpoint, and
// concurrently: it must be safe for concurrent use, and a policy that
// panics refuses the fetch with StatusUnavailable. An endpoint admitted
// here can fetch again, and read the roster of each epoch published
// while it remains admitted. A policy that should admit one fetch says
// so itself, checking the caller before it spends the fetch so that a
// stranger's probe does not spend it:
//
//	var used atomic.Bool
//	d.PublishGroupInfo(info, func(id key.EndpointID) bool {
//		return id.Equal(joiner) && used.CompareAndSwap(false, true)
//	})
func (d *Directory) PublishGroupInfo(info *mls.GroupInfo, policy func(key.EndpointID) bool) error {
	if info == nil {
		return errors.New("mlsiroh: nil group info")
	}
	var pub mls.ExternalPub
	if ok, err := info.Extensions.Decode(mls.ExtensionTypeExternalPub, &pub); err != nil {
		return fmt.Errorf("%w: external_pub extension: %w", ErrInvalidGroupInfo, err)
	} else if !ok {
		return fmt.Errorf("%w: no external_pub extension", ErrInvalidGroupInfo)
	}
	signer, err := verifyGroupInfo(info)
	if err != nil {
		return err
	}
	if !signer.Equal(d.id) {
		return fmt.Errorf("%w: group info signed by %v, serving %v", ErrWrongEndpoint, signer, d.id)
	}
	msg, err := mls.Marshal(&mls.Message{
		Version:    mls.Version10,
		WireFormat: mls.WireFormatGroupInfo,
		GroupInfo:  info,
	})
	if err != nil {
		return fmt.Errorf("mlsiroh: encoding group info: %w", err)
	}
	if len(msg) > MaxGroupInfoSize {
		return fmt.Errorf("mlsiroh: group info is %d bytes, over the %d limit", len(msg), MaxGroupInfoSize)
	}
	epoch := info.GroupContext.Epoch
	d.mu.Lock()
	defer d.mu.Unlock()
	id := string(info.GroupContext.GroupID)
	if g := d.groups[id]; g != nil && g.epoch > epoch {
		return fmt.Errorf("mlsiroh: group info for epoch %d, epoch %d is published", epoch, g.epoch)
	}
	d.groups[id] = &group{epoch: epoch, msg: msg, policy: policy}
	return nil
}

// WithdrawGroupInfo stops serving the GroupInfo of the named group if
// the one published is for epoch or earlier. A withdrawal that loses a
// race with the publication of a later epoch therefore leaves the
// later one published.
func (d *Directory) WithdrawGroupInfo(groupID []byte, epoch uint64) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if g := d.groups[string(groupID)]; g != nil && g.epoch <= epoch {
		delete(d.groups, string(groupID))
	}
}

// Welcomes returns the stream of Welcomes delivered to this directory,
// each paired with the endpoint that sent it. The stream ends when the
// directory is closed, after the Welcomes already accepted.
//
// A Welcome reaching this stream names a key package the directory
// served, but nothing else about it has been checked: it is the caller
// that decrypts it, and the caller that decides whether it wants to be
// in that group.
func (d *Directory) Welcomes() iter.Seq[Welcome] {
	return func(yield func(Welcome) bool) {
		for {
			// Queued Welcomes first. A plain select over both
			// channels picks at random when both are ready, so
			// closing the directory would drop Welcomes that
			// were already accepted and acknowledged.
			select {
			case w := <-d.welcomes:
				if !d.yieldWelcome(yield, w) {
					return
				}
				continue
			default:
			}
			select {
			case w := <-d.welcomes:
				if !d.yieldWelcome(yield, w) {
					return
				}
			case <-d.ctx.Done():
				for {
					select {
					case w := <-d.welcomes:
						if !d.yieldWelcome(yield, w) {
							return
						}
					default:
						return
					}
				}
			}
		}
	}
}

// yieldWelcome gives w's sender its share of the queue back and yields
// w.
func (d *Directory) yieldWelcome(yield func(Welcome) bool, w Welcome) bool {
	d.mu.Lock()
	if d.queued[w.From]--; d.queued[w.From] <= 0 {
		delete(d.queued, w.From)
	}
	d.mu.Unlock()
	return yield(w)
}

// Close stops the directory. A request arriving afterwards, or still
// being read, is answered StatusUnavailable; Close waits for requests
// being served to finish. The Welcomes stream ends once it has
// delivered the Welcomes already accepted.
func (d *Directory) Close() error {
	d.closemu.Lock()
	if d.closed {
		d.closemu.Unlock()
		return nil
	}
	d.closed = true
	d.cancel()
	d.closemu.Unlock()
	d.streams.Wait()
	return nil
}

// track counts a stream in d.streams unless the directory is closed.
// Close holds closemu while it marks the directory closed, so no
// stream is counted after Close starts to wait.
func (d *Directory) track() bool {
	d.closemu.Lock()
	defer d.closemu.Unlock()
	if d.closed {
		return false
	}
	d.streams.Add(1)
	return true
}

// Handler returns the protocol handler for the directory. Register it
// under [ALPN] on the endpoint's router.
func (d *Directory) Handler() iroh.ProtocolHandler { return (*handler)(d) }

type handler Directory

func (h *handler) Accept(ctx context.Context, conn *iroh.Conn) error {
	d := (*Directory)(h)
	// A 0-RTT connection has no verified peer until the handshake
	// completes: Conn.RemoteID is the zero id until then. Serving a
	// key package to a replayed 0-RTT request would drain the pool
	// on behalf of nobody.
	select {
	case <-conn.HandshakeComplete():
	case <-ctx.Done():
		return ctx.Err()
	case <-conn.Context().Done():
		return conn.Context().Err()
	}
	from := conn.RemoteID()
	for {
		stream, err := conn.AcceptStream(ctx)
		if err != nil {
			// The peer closed the connection, or the router is
			// shutting down. Neither is a failure of ours.
			return nil
		}
		if !d.track() {
			stream.CancelRead(0)
			d.reply(stream, StatusUnavailable, nil)
			stream.Close()
			continue
		}
		go func() {
			defer d.streams.Done()
			defer stream.Close()
			// One bad stream must not take down the connection:
			// other streams on it are independent requests.
			_ = d.serve(from, stream)
		}()
	}
}

// headerSize is the size of a request's version and op, which is what
// a handler reads before it knows how much more to accept.
const headerSize = 3

// serve reads one request from stream and writes its response.
func (d *Directory) serve(from key.EndpointID, stream *iroh.Stream) error {
	if err := stream.SetDeadline(time.Now().Add(readTimeout)); err != nil {
		return err
	}
	// Close must not wait out a slow sender.
	stop := context.AfterFunc(d.ctx, func() { stream.SetReadDeadline(time.Now()) })
	defer stop()

	// The header says which operation this is, and so how large the
	// rest may be: reading to the largest any operation allows before
	// knowing would let each stream hold MaxWelcomeSize.
	var hdr [headerSize]byte
	if _, err := io.ReadFull(stream, hdr[:]); err != nil {
		return d.readFailed(stream, err)
	}
	if binary.BigEndian.Uint16(hdr[:2]) != version {
		return d.reply(stream, StatusUnsupported, nil)
	}
	o := op(hdr[2])
	max := o.maxRequestSize()
	if max > MaxRequestSize {
		select {
		case d.large <- struct{}{}:
			defer func() { <-d.large }()
		case <-d.ctx.Done():
			return d.reply(stream, StatusUnavailable, nil)
		case <-time.After(readTimeout):
			return d.reply(stream, StatusUnavailable, nil)
		}
	}
	buf := bytes.NewBuffer(make([]byte, 0, min(max, MaxRequestSize)))
	buf.Write(hdr[:])
	if _, err := buf.ReadFrom(io.LimitReader(stream, int64(max-headerSize)+1)); err != nil {
		return d.readFailed(stream, err)
	}
	if buf.Len() > max {
		return d.reply(stream, StatusMalformed, nil)
	}
	var req request
	if err := mls.Unmarshal(buf.Bytes(), &req); err != nil {
		return d.reply(stream, StatusMalformed, nil)
	}
	status, body := d.dispatch(from, &req)
	return d.reply(stream, status, body)
}

// readFailed answers a request that could not be read in full: short
// requests are malformed, and a read cut off by Close is unavailable.
// Anything else is a broken stream, which gets no answer.
func (d *Directory) readFailed(stream *iroh.Stream, err error) error {
	if d.ctx.Err() != nil {
		return d.reply(stream, StatusUnavailable, nil)
	}
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return d.reply(stream, StatusMalformed, nil)
	}
	return err
}

// dispatch serves one decoded request. A closed directory serves
// nothing, and a panic - a policy is caller code - is answered
// StatusUnavailable rather than taking the process down.
func (d *Directory) dispatch(from key.EndpointID, req *request) (status Status, body []byte) {
	if d.ctx.Err() != nil {
		return StatusUnavailable, nil
	}
	defer func() {
		if recover() != nil {
			status, body = StatusUnavailable, nil
		}
	}()
	switch req.Op {
	case opFetchKeyPackage:
		return d.fetchKeyPackage(from, req.Body)
	case opDeliverWelcome:
		return d.deliverWelcome(from, req.Body)
	case opFetchGroupInfo:
		return d.fetchGroupInfo(from, req.Body)
	}
	return StatusUnsupported, nil
}

func (d *Directory) fetchKeyPackage(from key.EndpointID, body []byte) (Status, []byte) {
	var req fetchKeyPackageBody
	if err := mls.Unmarshal(body, &req); err != nil {
		return StatusMalformed, nil
	}
	// Each fetch spends a key package for good: take journals it before
	// it returns it, and Add refuses a key package the journal holds.
	// So an ungated pool is a pool any endpoint can empty and keep
	// empty.
	now := time.Now()
	d.mu.Lock()
	policy := d.poolPolicy
	// Counted before the policy is consulted, so probing costs the
	// prober its own budget.
	spare := d.fetches.allowCaller(from, now)
	d.mu.Unlock()
	// Every refusal answers exhausted, which is what an empty pool
	// answers. Whether this endpoint publishes key packages, and
	// whether it admits this caller, are not questions the caller gets
	// to distinguish; and an endpoint drawing too fast is being told
	// something true.
	if !spare || policy != nil && !policy(from) {
		return StatusExhausted, nil
	}
	if req.CipherSuite != Suite {
		return StatusUnsupported, nil
	}
	d.mu.Lock()
	spare = d.fetches.allowTotal(now)
	d.mu.Unlock()
	if !spare {
		return StatusExhausted, nil
	}
	b, found, err := d.take(req.CipherSuite)
	if !found {
		return StatusExhausted, nil
	}
	if err != nil {
		// The key package is still in the pool: a failure to
		// encode or to journal must not consume one. Say so, so
		// that the caller retries rather than concluding this
		// endpoint has nothing to offer.
		return StatusUnavailable, nil
	}
	return StatusOK, b
}

// take encodes and consumes one unexpired key package of the given
// suite. It reports false if the pool holds none. Expired key packages
// it meets on the way are dropped: serving one would spend it on a
// joiner whose client must refuse it.
//
// Everything happens under d.mu, and nothing leaves the pool unless all
// of it succeeded. The router serves each stream in its own goroutine,
// so a read followed by a delete would hand the same key package to two
// joiners. Consumption must be durable before the response is written
// or a crash re-serves a spent key package (RFC 9420, Sections 10 and
// 16.8); it must also be durable before the lock is released, or a
// concurrent [Directory.Add] can consult the journal in the window
// after the key package is gone and before it is recorded, and put it
// back.
func (d *Directory) take(suite mls.CipherSuite) ([]byte, bool, error) {
	now := time.Now()
	d.mu.Lock()
	defer d.mu.Unlock()
	for k, kp := range d.pool {
		if kp.CipherSuite != suite {
			continue
		}
		if expired(kp, now) {
			delete(d.pool, k)
			continue
		}
		b, err := mls.Marshal(&mls.Message{
			Version:    mls.Version10,
			WireFormat: mls.WireFormatKeyPackage,
			KeyPackage: kp,
		})
		if err != nil {
			return nil, true, err
		}
		e, err := entry(kp)
		if err != nil {
			return nil, true, err
		}
		if err := d.journal.Record(e); err != nil {
			return nil, true, err
		}
		delete(d.pool, k)
		return b, true, nil
	}
	return nil, false, nil
}

func expired(kp *mls.KeyPackage, now time.Time) bool {
	return now.Unix() > 0 && kp.LeafNode.Lifetime.NotAfter < uint64(now.Unix())
}

func (d *Directory) deliverWelcome(from key.EndpointID, body []byte) (Status, []byte) {
	if len(body) > MaxWelcomeSize {
		return StatusMalformed, nil
	}
	now := time.Now()
	d.mu.Lock()
	spare := d.deliveries.allowCaller(from, now) && d.deliveries.allowTotal(now)
	d.mu.Unlock()
	if !spare {
		return StatusExhausted, nil
	}
	var msg mls.Message
	if err := mls.Unmarshal(body, &msg); err != nil {
		return StatusMalformed, nil
	}
	if msg.WireFormat != mls.WireFormatWelcome || msg.Welcome == nil {
		return StatusMalformed, nil
	}
	e, ok, err := d.addressed(msg.Welcome, now)
	if err != nil {
		return StatusUnavailable, nil
	}
	if !ok {
		// The same answer as for anything else the caller may not
		// have. See the Security section of the package doc for
		// what it still tells a caller that can name a reference.
		return StatusNotFound, nil
	}

	d.mu.Lock()
	defer d.mu.Unlock()
	dl := d.delivered[string(e.Ref)]
	if dl.n >= maxWelcomesPerKeyPackage {
		return StatusExhausted, nil
	}
	if d.queued[from] >= maxQueuedPerSender {
		return StatusUnavailable, nil
	}
	select {
	case d.welcomes <- Welcome{From: from, Message: msg.Welcome}:
		d.delivered[string(e.Ref)] = delivered{n: dl.n + 1, notAfter: e.NotAfter}
		d.queued[from]++
		return StatusOK, nil
	default:
		// Nobody is draining the stream. Saying so is better than
		// blocking a handler that holds a stream deadline, and
		// the sender should try again.
		return StatusUnavailable, nil
	}
}

// addressed returns the journal entry of the first key package w names
// that this directory served and still routes Welcomes for. The routing
// key is already in the protocol — a Welcome names its recipients by
// key package reference — so naming the recipient out of band would be
// a side channel. The journal is what makes the routing survive a
// restart.
//
// The lookup is a hit per secret rather than a scan, because a scan
// would be a hash per served package per secret, which a large Welcome
// turns into a denial of service.
func (d *Directory) addressed(w *mls.Welcome, now time.Time) (Entry, bool, error) {
	for i := range w.Secrets {
		e, ok, err := d.journal.Lookup(w.Secrets[i].NewMember)
		if err != nil {
			return Entry{}, false, err
		}
		if ok && routable(e.NotAfter, now) {
			return e, true, nil
		}
	}
	return Entry{}, false, nil
}

// welcomeGrace is how long past a key package's lifetime a Welcome
// naming it is still routed. RFC 9420, Section 7.3, enforces a
// lifetime when a key package is used, not when it is received, so a
// key package can expire in flight and the Welcome that carries it is
// still worth delivering; the joining client is the one that decides.
const welcomeGrace = 24 * time.Hour

func routable(notAfter uint64, now time.Time) bool {
	cutoff := now.Add(-welcomeGrace).Unix()
	return cutoff < 0 || notAfter >= uint64(cutoff)
}

// forgetExpired drops expired key packages from the pool, and the
// delivery counts of key packages no Welcome is routed for any more.
//
// d.mu must be held.
func (d *Directory) forgetExpired(now time.Time) {
	for k, kp := range d.pool {
		if expired(kp, now) {
			delete(d.pool, k)
		}
	}
	for ref, dl := range d.delivered {
		if !routable(dl.notAfter, now) {
			delete(d.delivered, ref)
		}
	}
}

func (d *Directory) fetchGroupInfo(from key.EndpointID, body []byte) (Status, []byte) {
	var req fetchGroupInfoBody
	if err := mls.Unmarshal(body, &req); err != nil {
		return StatusMalformed, nil
	}
	d.mu.Lock()
	g := d.groups[string(req.GroupID)]
	d.mu.Unlock()
	// An unauthorized caller and an unknown group are reported the
	// same way, so that the endpoint does not confirm a group's
	// existence to a peer that may not join it.
	if g == nil || g.policy == nil || !g.policy(from) {
		return StatusNotFound, nil
	}
	return StatusOK, g.msg
}

func (d *Directory) reply(stream *iroh.Stream, status Status, body []byte) error {
	b, err := mls.Marshal(&response{Version: version, Status: status, Body: body})
	if err != nil {
		return err
	}
	if _, err := stream.Write(b); err != nil {
		return err
	}
	return stream.CloseWrite()
}
