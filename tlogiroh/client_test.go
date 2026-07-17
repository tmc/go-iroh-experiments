package tlogiroh

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/tmc/go-iroh/blobs"
	"github.com/tmc/go-iroh/docs"
)

// appendAndPublish appends entries numbered [size(op), n) and publishes,
// returning the signed checkpoint message.
func appendAndPublish(t *testing.T, op *Operator, n int64) []byte {
	t.Helper()
	ctx := context.Background()
	for op.Size() < n {
		if _, err := op.Append(ctx, fmt.Appendf(nil, `{"n":%d}`, op.Size())); err != nil {
			t.Fatal(err)
		}
	}
	msg, err := op.Publish(ctx)
	if err != nil {
		t.Fatal(err)
	}
	return msg
}

func TestClientSyncAndEntry(t *testing.T) {
	op, _, policy := newTestLog(t)
	ctx := context.Background()
	client := NewClient(policy, op.Source())

	if _, err := client.Sync(ctx); !errors.Is(err, ErrNoCheckpoint) {
		t.Fatalf("Sync of empty source = %v, want ErrNoCheckpoint", err)
	}
	if _, err := client.Entry(ctx, 0); !errors.Is(err, ErrNoCheckpoint) {
		t.Fatalf("Entry with no head = %v, want ErrNoCheckpoint", err)
	}

	appendAndPublish(t, op, 10)
	head, err := client.Sync(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if head.Tree.N != 10 {
		t.Fatalf("head size = %d, want 10", head.Tree.N)
	}
	for i := range int64(10) {
		data, err := client.Entry(ctx, i)
		if err != nil {
			t.Fatal(err)
		}
		want := fmt.Appendf(nil, `{"n":%d}`, i)
		if !bytes.Equal(data, want) {
			t.Fatalf("entry %d = %q, want %q", i, data, want)
		}
	}
	if _, err := client.Entry(ctx, 10); err == nil {
		t.Fatal("Entry(10) beyond head succeeded, want error")
	}
	if _, err := client.Entry(ctx, -1); err == nil {
		t.Fatal("Entry(-1) succeeded, want error")
	}
}

func TestClientConsistencyAndRollback(t *testing.T) {
	op, _, policy := newTestLog(t)
	ctx := context.Background()
	client := NewClient(policy, op.Source())

	msg10 := appendAndPublish(t, op, 10)
	if _, err := client.Update(ctx, msg10); err != nil {
		t.Fatal(err)
	}

	appendAndPublish(t, op, 25)
	head, err := client.Sync(ctx)
	if err != nil {
		t.Fatalf("consistency update: %v", err)
	}
	if head.Tree.N != 25 {
		t.Fatalf("head size = %d, want 25", head.Tree.N)
	}

	if _, err := client.Update(ctx, msg10); !errors.Is(err, ErrRollback) {
		t.Fatalf("Update with old checkpoint = %v, want ErrRollback", err)
	}
}

func TestClientHeadPersistence(t *testing.T) {
	op, _, policy := newTestLog(t)
	ctx := context.Background()
	client := NewClient(policy, op.Source())

	msg10 := appendAndPublish(t, op, 10)
	if _, err := client.Update(ctx, msg10); err != nil {
		t.Fatal(err)
	}
	saved := client.HeadNote()
	if saved == nil {
		t.Fatal("HeadNote = nil after update")
	}

	restored := NewClient(policy, op.Source())
	if err := restored.SetHead(saved); err != nil {
		t.Fatal(err)
	}
	head, ok := restored.Head()
	if !ok || head.Tree.N != 10 {
		t.Fatalf("restored head = %+v %v, want size 10", head, ok)
	}

	appendAndPublish(t, op, 20)
	if _, err := restored.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	if err := restored.SetHead(saved); !errors.Is(err, ErrRollback) {
		t.Fatalf("SetHead with older head = %v, want ErrRollback", err)
	}
}

func TestClientEquivocation(t *testing.T) {
	op, verifier, policy := newTestLog(t)
	ctx := context.Background()

	// A second operator with the same signing key and origin but different
	// content is a split view.
	twin, err := NewOperator(testOrigin, op.signer)
	if err != nil {
		t.Fatal(err)
	}
	msg := appendAndPublish(t, op, 10)
	twinMsg := func() []byte {
		for twin.Size() < 10 {
			if _, err := twin.Append(ctx, fmt.Appendf(nil, `{"twin":%d}`, twin.Size())); err != nil {
				t.Fatal(err)
			}
		}
		m, err := twin.Publish(ctx)
		if err != nil {
			t.Fatal(err)
		}
		return m
	}()

	client := NewClient(policy, op.Source())
	if _, err := client.Update(ctx, msg); err != nil {
		t.Fatal(err)
	}
	_, err = client.Update(ctx, twinMsg)
	var equiv *EquivocationError
	if !errors.As(err, &equiv) {
		t.Fatalf("Update with split view = %v, want *EquivocationError", err)
	}
	size, err := VerifyEquivocation(equiv.Proof, testOrigin, verifier)
	if err != nil {
		t.Fatal(err)
	}
	if size != 10 {
		t.Fatalf("equivocated size = %d, want 10", size)
	}
}

func TestClientTamperedEntry(t *testing.T) {
	op, _, policy := newTestLog(t)
	ctx := context.Background()

	appendAndPublish(t, op, 10)
	src := op.Source()
	honest := src.Get
	victim, ok := src.Doc.GetExact(src.Namespace, src.Author, []byte(entryKey(3)), false)
	if !ok {
		t.Fatal("entry 3 missing from timeline")
	}
	src.Get = func(ctx context.Context, hash blobs.Hash) ([]byte, error) {
		data, e := honest(ctx, hash)
		if e == nil && hash == victim.Entry.Record.Hash {
			tampered := append([]byte{}, data...)
			tampered[len(tampered)-2] ^= 1
			return tampered, nil
		}
		return data, e
	}

	client := NewClient(policy, src)
	if _, err := client.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Entry(ctx, 3); err == nil {
		t.Fatal("Entry(3) with tampered blob succeeded, want error")
	}
	if _, err := client.Entry(ctx, 4); err != nil {
		t.Fatalf("Entry(4) with honest blob failed: %v", err)
	}
}

// TestClientUpdateStaleSource pins the stale-source classification: a
// checkpoint larger than the head fails with errSourceStale while the doc
// replica lacks the new tiles, leaves the head unchanged, and verifies once
// the replica catches up.
func TestClientUpdateStaleSource(t *testing.T) {
	op, _, policy := newTestLog(t)
	ctx := context.Background()

	msg5 := appendAndPublish(t, op, 5)
	replica := docs.NewMemoryStore()
	copyDoc := func() {
		for _, entry := range op.Doc().Entries() {
			replica.Put(entry)
		}
	}
	copyDoc()
	src := op.Source()
	src.Doc = replica
	client := NewClient(policy, src)
	if _, err := client.Update(ctx, msg5); err != nil {
		t.Fatal(err)
	}

	msg12 := appendAndPublish(t, op, 12)
	if _, err := client.Update(ctx, msg12); !errors.Is(err, errSourceStale) {
		t.Fatalf("Update with stale replica = %v, want errSourceStale", err)
	}
	if head, _ := client.Head(); head.Tree.N != 5 {
		t.Fatalf("head after stale update = %d, want 5", head.Tree.N)
	}

	copyDoc()
	cp, err := client.Update(ctx, msg12)
	if err != nil {
		t.Fatalf("Update after replica caught up: %v", err)
	}
	if cp.Tree.N != 12 {
		t.Fatalf("updated head = %d, want 12", cp.Tree.N)
	}
}
