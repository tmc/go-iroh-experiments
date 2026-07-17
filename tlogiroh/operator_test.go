package tlogiroh

import (
	"bytes"
	"context"
	"crypto/rand"
	"fmt"
	"sync"
	"testing"

	"golang.org/x/mod/sumdb/note"
	"golang.org/x/mod/sumdb/tlog"
)

const testOrigin = "example.org/tlog-test"

// newTestLog returns an operator, its note verifier, and a K=0 policy.
func newTestLog(t *testing.T) (*Operator, note.Verifier, Policy) {
	t.Helper()
	skey, vkey, err := note.GenerateKey(rand.Reader, testOrigin)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := note.NewSigner(skey)
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := note.NewVerifier(vkey)
	if err != nil {
		t.Fatal(err)
	}
	op, err := NewOperator(testOrigin, signer)
	if err != nil {
		t.Fatal(err)
	}
	policy, err := NewPolicy(testOrigin, verifier, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	return op, verifier, policy
}

// checkTree verifies every entry of the published tree through the source's
// authenticated tiles: inclusion proofs for each index against the
// checkpoint root.
func checkTree(t *testing.T, src Source, c Checkpoint, entries [][]byte) {
	t.Helper()
	ctx := context.Background()
	hr := src.hashReaderForTree(ctx, c.Tree)
	for i, want := range entries {
		data, err := src.blob(ctx, entryKey(int64(i)))
		if err != nil {
			t.Fatalf("entry %d: %v", i, err)
		}
		if !bytes.Equal(data, want) {
			t.Fatalf("entry %d = %q, want %q", i, data, want)
		}
		proof, err := tlog.ProveRecord(c.Tree.N, int64(i), hr)
		if err != nil {
			t.Fatalf("prove record %d: %v", i, err)
		}
		if err := tlog.CheckRecord(proof, c.Tree.N, c.Tree.Hash, int64(i), tlog.RecordHash(data)); err != nil {
			t.Fatalf("check record %d: %v", i, err)
		}
	}
}

func TestOperatorEmptyPublish(t *testing.T) {
	op, _, policy := newTestLog(t)
	msg, err := op.Publish(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	c, err := policy.Open(msg)
	if err != nil {
		t.Fatal(err)
	}
	if c.Tree.N != 0 {
		t.Errorf("empty publish tree size = %d, want 0", c.Tree.N)
	}
	if op.SignedCheckpoint() == nil {
		t.Error("SignedCheckpoint = nil after Publish")
	}
}

func TestOperatorAppendPublish(t *testing.T) {
	op, _, policy := newTestLog(t)
	ctx := context.Background()

	var entries [][]byte
	for i := range 10 {
		entry := fmt.Appendf(nil, `{"n":%d}`, i)
		index, err := op.Append(ctx, entry)
		if err != nil {
			t.Fatal(err)
		}
		if index != int64(i) {
			t.Fatalf("Append #%d returned index %d", i, index)
		}
		entries = append(entries, entry)
	}
	if op.Size() != 10 {
		t.Fatalf("Size = %d, want 10", op.Size())
	}

	msg, err := op.Publish(ctx)
	if err != nil {
		t.Fatal(err)
	}
	c, err := policy.Open(msg)
	if err != nil {
		t.Fatal(err)
	}
	if c.Origin != testOrigin || c.Tree.N != 10 {
		t.Fatalf("checkpoint = %+v, want origin %q size 10", c, testOrigin)
	}
	checkTree(t, op.Source(), c, entries)

	// Publishing an unchanged tree re-signs to identical bytes
	// (deterministic Ed25519; see the freeze-attack note in doc.go).
	again, err := op.Publish(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(msg, again) {
		t.Error("republish of unchanged tree differs from original")
	}
}

// TestOperatorMultiLevelTiles crosses the 2^TileHeight boundary so the tree
// needs level-1 tiles, and publishes in increments so verification spans
// tiles from several publishes.
func TestOperatorMultiLevelTiles(t *testing.T) {
	op, _, policy := newTestLog(t)
	ctx := context.Background()

	var entries [][]byte
	appendTo := func(n int) {
		for len(entries) < n {
			entry := fmt.Appendf(nil, `{"n":%d}`, len(entries))
			if _, err := op.Append(ctx, entry); err != nil {
				t.Fatal(err)
			}
			entries = append(entries, entry)
		}
	}

	var last Checkpoint
	for _, size := range []int{100, 256, 300} {
		appendTo(size)
		msg, err := op.Publish(ctx)
		if err != nil {
			t.Fatal(err)
		}
		last, err = policy.Open(msg)
		if err != nil {
			t.Fatal(err)
		}
		if last.Tree.N != int64(size) {
			t.Fatalf("checkpoint size = %d, want %d", last.Tree.N, size)
		}
	}
	checkTree(t, op.Source(), last, entries)
}

// TestOperatorOldCheckpointStaysVerifiable pins the property that makes the
// tileReader exact-width check sound: after later publishes widen the edge
// tiles, the partial tiles of earlier checkpoints remain under their own
// .p/W timeline keys, so proofs against an old checkpoint still verify.
func TestOperatorOldCheckpointStaysVerifiable(t *testing.T) {
	op, _, policy := newTestLog(t)
	ctx := context.Background()

	var entries [][]byte
	for len(entries) < 100 {
		entry := fmt.Appendf(nil, `{"n":%d}`, len(entries))
		if _, err := op.Append(ctx, entry); err != nil {
			t.Fatal(err)
		}
		entries = append(entries, entry)
	}
	oldMsg, err := op.Publish(ctx)
	if err != nil {
		t.Fatal(err)
	}
	old, err := policy.Open(oldMsg)
	if err != nil {
		t.Fatal(err)
	}

	for len(entries) < 300 {
		entry := fmt.Appendf(nil, `{"n":%d}`, len(entries))
		if _, err := op.Append(ctx, entry); err != nil {
			t.Fatal(err)
		}
		entries = append(entries, entry)
	}
	if _, err := op.Publish(ctx); err != nil {
		t.Fatal(err)
	}

	checkTree(t, op.Source(), old, entries[:100])
}

func TestOperatorConcurrentAppend(t *testing.T) {
	op, _, policy := newTestLog(t)
	ctx := context.Background()

	var wg sync.WaitGroup
	seen := make([]bool, 64)
	var mu sync.Mutex
	for range 8 {
		wg.Go(func() {
			for range 8 {
				index, err := op.Append(ctx, []byte("entry"))
				if err != nil {
					t.Error(err)
					return
				}
				mu.Lock()
				if seen[index] {
					t.Errorf("index %d appended twice", index)
				}
				seen[index] = true
				mu.Unlock()
			}
		})
	}
	wg.Wait()

	msg, err := op.Publish(ctx)
	if err != nil {
		t.Fatal(err)
	}
	c, err := policy.Open(msg)
	if err != nil {
		t.Fatal(err)
	}
	if c.Tree.N != 64 {
		t.Fatalf("tree size = %d, want 64", c.Tree.N)
	}
}
