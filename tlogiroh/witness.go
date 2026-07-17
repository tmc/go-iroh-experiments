package tlogiroh

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/tmc/go-iroh/gossip"
	"golang.org/x/mod/sumdb/note"
	"golang.org/x/mod/sumdb/tlog"
)

// A Witness verifies checkpoint consistency and countersigns what it
// accepts. It stores its latest cosigned checkpoint in memory as its head
// and refuses rollback and equivocation like a client, but does not require
// other witnesses' cosignatures. A Witness is safe for concurrent use.
type Witness struct {
	signer   note.Signer
	origin   string
	operator note.Verifier
	src      Source

	mu      sync.Mutex
	headMsg []byte
	head    Checkpoint
	hasHead bool
}

// NewWitness returns a witness for the log named origin, verifying the
// operator signature with operator, fetching tiles through src, and
// cosigning with signer.
func NewWitness(signer note.Signer, origin string, operator note.Verifier, src Source) *Witness {
	return &Witness{signer: signer, origin: origin, operator: operator, src: src}
}

// Head returns the latest cosigned checkpoint, if any.
func (w *Witness) Head() (Checkpoint, bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.head, w.hasHead
}

// Cosign verifies the signed checkpoint message and returns it with the
// witness signature appended. A tree larger than the witness head must
// prove consistency; an equal tree must match exactly (else
// *EquivocationError); a smaller tree returns ErrRollback. The first
// checkpoint is trust-on-first-use.
func (w *Witness) Cosign(ctx context.Context, msg []byte) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.cosign(ctx, msg)
}

// cosign is the regeneratable core of Cosign. It runs with w.mu held.
func (w *Witness) cosign(ctx context.Context, msg []byte) ([]byte, error) {
	n, err := note.Open(msg, note.VerifierList(w.operator))
	if err != nil {
		return nil, fmt.Errorf("tlogiroh: open checkpoint: %w", err)
	}
	cp, err := ParseCheckpoint([]byte(n.Text))
	if err != nil {
		return nil, err
	}
	if cp.Origin != w.origin {
		return nil, fmt.Errorf("%w: checkpoint names %q, witness serves %q", ErrOriginMismatch, cp.Origin, w.origin)
	}
	if w.hasHead {
		switch {
		case cp.Tree.N < w.head.Tree.N:
			return nil, fmt.Errorf("%w: got size %d, head size %d", ErrRollback, cp.Tree.N, w.head.Tree.N)
		case cp.Tree.N == w.head.Tree.N:
			if cp.Tree.Hash != w.head.Tree.Hash {
				return nil, &EquivocationError{Proof: Equivocation{First: w.headMsg, Second: msg}}
			}
		case w.head.Tree.N > 0:
			hashes := w.src.hashReaderForTree(ctx, cp.Tree)
			proof, err := tlog.ProveTree(cp.Tree.N, w.head.Tree.N, hashes)
			if err != nil {
				return nil, fmt.Errorf("tlogiroh: prove consistency: %w", err)
			}
			if err := tlog.CheckTree(proof, cp.Tree.N, cp.Tree.Hash, w.head.Tree.N, w.head.Tree.Hash); err != nil {
				return nil, fmt.Errorf("tlogiroh: check consistency: %w", err)
			}
		}
	}
	// Preserve cosignatures by keys this witness does not know (other
	// witnesses); note.Sign drops UnverifiedSigs otherwise.
	n.Sigs = append(n.Sigs, n.UnverifiedSigs...)
	n.UnverifiedSigs = nil
	cosigned, err := note.Sign(n, w.signer)
	if err != nil {
		return nil, fmt.Errorf("tlogiroh: cosign checkpoint: %w", err)
	}
	w.headMsg, w.head, w.hasHead = cosigned, cp, true
	return cosigned, nil
}

// Run subscribes to checkpoint announcements on the gossip topic, cosigns
// each acceptable checkpoint, and broadcasts the cosigned message. Detected
// equivocations are broadcast as proofs. Run returns when ctx is done or
// the topic closes; close the topic after canceling ctx to release the
// event stream promptly.
func (w *Witness) Run(ctx context.Context, topic *gossip.Topic) error {
	return w.run(ctx, topic)
}

// run is the regeneratable core of Run.
func (w *Witness) run(ctx context.Context, topic *gossip.Topic) error {
	flooded := make(map[string]bool) // equivocation proofs already rebroadcast
	events := topicMessages(ctx, topic)
	for {
		var content []byte
		select {
		case <-ctx.Done():
			return ctx.Err()
		case msg, ok := <-events:
			if !ok {
				return nil
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
			if _, err := VerifyEquivocation(proof, w.origin, w.operator); err != nil {
				continue
			}
			if !flooded[string(payload)] {
				flooded[string(payload)] = true
				topic.Broadcast(ctx, envelope(envEquivocation, payload))
			}
		case envCheckpoint:
			cosigned, err := w.Cosign(ctx, payload)
			equiv, isEquiv := errors.AsType[*EquivocationError](err)
			switch {
			case err == nil:
				topic.Broadcast(ctx, envelope(envCheckpoint, cosigned))
			case isEquiv:
				if data, err := equiv.Proof.MarshalBinary(); err == nil && !flooded[string(data)] {
					flooded[string(data)] = true
					topic.Broadcast(ctx, envelope(envEquivocation, data))
				}
			}
			// Rollback, origin, and signature failures are stale or
			// malicious announcements: ignore them and keep running.
		}
	}
}
