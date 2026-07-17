package tlogiroh

import (
	"context"
	"errors"
	"fmt"
	"iter"
	"sync"
	"time"

	"github.com/tmc/go-iroh/gossip"
	"golang.org/x/mod/sumdb/tlog"
)

// errSourceStale marks a verification failure that a fresher source may
// resolve: the doc replica has not yet caught up to the announced tree.
// Gossip deduplicates the byte-identical re-announcements of a deterministic
// checkpoint, so each peer sees a given checkpoint once; Watch and Run park
// checkpoints that fail this way and retry them as the replica syncs.
var errSourceStale = errors.New("tlogiroh: source not caught up")

// staleRetryInterval is how often Watch and Run retry parked checkpoints.
// It is a variable to let tests shorten it.
var staleRetryInterval = 2 * time.Second

// A Client reads and verifies a transparency log against a Policy. It
// stores the latest accepted signed checkpoint (the head) in memory; use
// HeadNote and SetHead to persist it across restarts. Update and Sync
// enforce the policy: operator signature, K witness cosignatures, no
// rollback, and a consistency proof from the stored head. The first
// accepted checkpoint is trust-on-first-use. A Client is safe for
// concurrent use.
type Client struct {
	policy Policy
	src    Source

	mu      sync.Mutex
	headMsg []byte
	head    Checkpoint
	hasHead bool
}

// NewClient returns a client reading the log from src and enforcing policy.
func NewClient(policy Policy, src Source) *Client {
	return &Client{policy: policy, src: src}
}

// Head returns the latest accepted checkpoint, if any.
func (c *Client) Head() (Checkpoint, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.head, c.hasHead
}

// HeadNote returns the signed note message of the latest accepted
// checkpoint, or nil. Callers persist it and restore with SetHead.
func (c *Client) HeadNote() []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.headMsg
}

// SetHead restores a previously accepted head from its signed note message,
// verifying it against the policy first.
func (c *Client) SetHead(msg []byte) error {
	cp, err := c.policy.Open(msg)
	if err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.hasHead {
		if cp.Tree.N < c.head.Tree.N {
			return fmt.Errorf("%w: restoring size %d over head size %d", ErrRollback, cp.Tree.N, c.head.Tree.N)
		}
		if cp.Tree.N == c.head.Tree.N && cp.Tree.Hash != c.head.Tree.Hash {
			return &EquivocationError{Proof: Equivocation{First: c.headMsg, Second: msg}}
		}
	}
	c.headMsg, c.head, c.hasHead = msg, cp, true
	return nil
}

// Update verifies the signed checkpoint message msg and advances the head.
// It returns ErrWitnessThreshold, ErrOriginMismatch, ErrRollback, or an
// *EquivocationError as the policy and stored head demand; on a tree larger
// than the head it fetches tiles through the source and checks a
// consistency proof before accepting.
func (c *Client) Update(ctx context.Context, msg []byte) (Checkpoint, error) {
	if err := ctx.Err(); err != nil {
		return Checkpoint{}, err
	}
	cp, err := c.policy.Open(msg)
	if err != nil {
		return Checkpoint{}, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.update(ctx, cp, msg)
}

// update is the regeneratable core of Update. It runs with c.mu held; cp is
// the already policy-verified checkpoint carried by msg.
func (c *Client) update(ctx context.Context, cp Checkpoint, msg []byte) (Checkpoint, error) {
	if c.hasHead {
		switch {
		case cp.Tree.N < c.head.Tree.N:
			return Checkpoint{}, fmt.Errorf("%w: got size %d, head size %d", ErrRollback, cp.Tree.N, c.head.Tree.N)
		case cp.Tree.N == c.head.Tree.N:
			if cp.Tree.Hash != c.head.Tree.Hash {
				return Checkpoint{}, &EquivocationError{Proof: Equivocation{First: c.headMsg, Second: msg}}
			}
			if merged, err := mergeSignedNotes(c.headMsg, msg); err == nil {
				c.headMsg = merged
			}
			return c.head, nil
		case c.head.Tree.N > 0:
			hashes := c.src.hashReaderForTree(ctx, cp.Tree)
			proof, err := tlog.ProveTree(cp.Tree.N, c.head.Tree.N, hashes)
			if err != nil {
				// Proving reads tiles through the source; failure here means
				// the replica lacks the new tree, not that the tree is bad.
				return Checkpoint{}, fmt.Errorf("%w: prove consistency: %w", errSourceStale, err)
			}
			if err := tlog.CheckTree(proof, cp.Tree.N, cp.Tree.Hash, c.head.Tree.N, c.head.Tree.Hash); err != nil {
				return Checkpoint{}, fmt.Errorf("tlogiroh: check consistency: %w", err)
			}
		}
	}
	c.headMsg, c.head, c.hasHead = msg, cp, true
	return cp, nil
}

// Sync reads the latest published checkpoint from the log source and
// applies Update. It returns ErrNoCheckpoint if the source has none.
func (c *Client) Sync(ctx context.Context) (Checkpoint, error) {
	msg, err := c.src.latestCheckpoint(ctx)
	if err != nil {
		return Checkpoint{}, err
	}
	return c.Update(ctx, msg)
}

// Entry fetches the log entry at index and verifies its inclusion proof
// against the stored head. It returns ErrNoCheckpoint if the client has no
// head, or an error if index is outside the head tree.
func (c *Client) Entry(ctx context.Context, index int64) ([]byte, error) {
	c.mu.Lock()
	head, ok := c.head, c.hasHead
	c.mu.Unlock()
	if !ok {
		return nil, ErrNoCheckpoint
	}
	return c.entry(ctx, head, index)
}

// entry is the regeneratable core of Entry.
func (c *Client) entry(ctx context.Context, head Checkpoint, index int64) ([]byte, error) {
	if index < 0 || index >= head.Tree.N {
		return nil, fmt.Errorf("tlogiroh: entry %d outside head tree of size %d", index, head.Tree.N)
	}
	data, err := c.src.blob(ctx, entryKey(index))
	if err != nil {
		return nil, err
	}
	hashes := c.src.hashReaderForTree(ctx, head.Tree)
	proof, err := tlog.ProveRecord(head.Tree.N, index, hashes)
	if err != nil {
		return nil, fmt.Errorf("tlogiroh: prove entry %d: %w", index, err)
	}
	if err := tlog.CheckRecord(proof, head.Tree.N, head.Tree.Hash, index, tlog.RecordHash(data)); err != nil {
		return nil, fmt.Errorf("tlogiroh: check entry %d: %w", index, err)
	}
	return data, nil
}

// Watch consumes checkpoint announcements from the gossip topic, merging
// witness cosignatures for identical checkpoints, and yields each
// checkpoint once it satisfies the policy and Update accepts it. A
// checkpoint that cannot be verified yet because the source has not caught
// up to it is retried periodically until it is accepted or superseded. If
// Watch observes or receives proof of equivocation it broadcasts the proof
// on the topic and yields the *EquivocationError. Watch returns when ctx is
// done or the topic closes; close the topic after canceling ctx to release
// the event stream promptly.
func (c *Client) Watch(ctx context.Context, topic *gossip.Topic) iter.Seq2[Checkpoint, error] {
	return func(yield func(Checkpoint, error) bool) {
		c.watch(ctx, topic, yield)
	}
}

// watch is the regeneratable core of Watch.
func (c *Client) watch(ctx context.Context, topic *gossip.Topic, yield func(Checkpoint, error) bool) {
	pending := make(map[string][]byte) // checkpoint text -> best merged message, awaiting cosignatures or a fresher source
	flooded := make(map[string]bool)   // equivocation proofs already rebroadcast
	var lastYielded Checkpoint
	// process attempts msg, filing it under its checkpoint text in pending
	// when a later retry may succeed. It reports whether to keep watching.
	// Only messages that carry a valid operator signature can enter pending:
	// threshold and staleness are diagnosed after the note is opened.
	process := func(text string, msg []byte) bool {
		cp, err := c.Update(ctx, msg)
		equiv, isEquiv := errors.AsType[*EquivocationError](err)
		switch {
		case err == nil:
			delete(pending, text)
			if cp != lastYielded {
				lastYielded = cp
				if !yield(cp, nil) {
					return false
				}
			}
		case errors.Is(err, ErrWitnessThreshold), errors.Is(err, errSourceStale):
			pending[text] = msg
		case isEquiv:
			delete(pending, text)
			if data, err := equiv.Proof.MarshalBinary(); err == nil && !flooded[string(data)] {
				flooded[string(data)] = true
				topic.Broadcast(ctx, envelope(envEquivocation, data))
			}
			if !yield(Checkpoint{}, equiv) {
				return false
			}
		default:
			// Rollback, origin, and signature failures are stale or
			// malicious announcements: drop them and keep watching.
			delete(pending, text)
		}
		return true
	}
	retry := time.NewTicker(staleRetryInterval)
	defer retry.Stop()
	events := topicMessages(ctx, topic)
	for {
		var content []byte
		select {
		case <-ctx.Done():
			return
		case <-retry.C:
			for text, msg := range pending {
				if !process(text, msg) {
					return
				}
			}
			continue
		case msg, ok := <-events:
			if !ok {
				return
			}
			content = msg
		}
		kind, payload, ok := openEnvelope(content)
		if !ok {
			continue
		}
		switch kind {
		case envEquivocation:
			var proof Equivocation
			if err := proof.UnmarshalBinary(payload); err != nil {
				continue
			}
			if _, err := VerifyEquivocation(proof, c.policy.origin, c.policy.operator); err != nil {
				continue
			}
			if !flooded[string(payload)] {
				flooded[string(payload)] = true
				topic.Broadcast(ctx, envelope(envEquivocation, payload))
			}
			if !yield(Checkpoint{}, &EquivocationError{Proof: proof}) {
				return
			}
		case envCheckpoint:
			text, _, err := splitNote(payload)
			if err != nil {
				continue
			}
			msg := payload
			if prev, ok := pending[string(text)]; ok {
				if merged, err := mergeSignedNotes(prev, payload); err == nil {
					msg = merged
				}
			}
			if !process(string(text), msg) {
				return
			}
		}
	}
}

// topicMessages forwards the application payloads received on topic into a
// channel, following the forwarding-goroutine shape of docs.LiveSync. The
// channel closes when the topic closes; the goroutine exits with the topic
// or when ctx is done at the next event.
func topicMessages(ctx context.Context, topic *gossip.Topic) <-chan []byte {
	out := make(chan []byte)
	go func() {
		defer close(out)
		for ev, err := range topic.Events() {
			if err != nil || ev.Kind != gossip.Received {
				continue
			}
			select {
			case out <- ev.Content:
			case <-ctx.Done():
				return
			}
		}
	}()
	return out
}
