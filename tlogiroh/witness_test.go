package tlogiroh

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"testing"

	"golang.org/x/mod/sumdb/note"
)

// newTestWitness returns a witness reading from src and its verifier key.
func newTestWitness(t *testing.T, name string, operator note.Verifier, src Source) (*Witness, note.Verifier) {
	t.Helper()
	skey, vkey, err := note.GenerateKey(rand.Reader, name)
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
	return NewWitness(signer, testOrigin, operator, src), verifier
}

func TestWitnessCosignThreshold(t *testing.T) {
	op, opVerifier, _ := newTestLog(t)
	ctx := context.Background()

	w1, v1 := newTestWitness(t, "witness.one", opVerifier, op.Source())
	w2, v2 := newTestWitness(t, "witness.two", opVerifier, op.Source())
	policy2, err := NewPolicy(testOrigin, opVerifier, []note.Verifier{v1, v2}, 2)
	if err != nil {
		t.Fatal(err)
	}

	msg := appendAndPublish(t, op, 5)

	cos1, err := w1.Cosign(ctx, msg)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := policy2.Open(cos1); !errors.Is(err, ErrWitnessThreshold) {
		t.Fatalf("Open with one cosignature = %v, want ErrWitnessThreshold", err)
	}

	// The second witness cosigns the already-cosigned message and must
	// preserve the first witness's signature.
	cos12, err := w2.Cosign(ctx, cos1)
	if err != nil {
		t.Fatal(err)
	}
	cp, err := policy2.Open(cos12)
	if err != nil {
		t.Fatalf("Open with two cosignatures: %v", err)
	}
	if cp.Tree.N != 5 {
		t.Fatalf("checkpoint size = %d, want 5", cp.Tree.N)
	}

	client := NewClient(policy2, op.Source())
	if _, err := client.Update(ctx, msg); !errors.Is(err, ErrWitnessThreshold) {
		t.Fatalf("client Update without cosignatures = %v, want ErrWitnessThreshold", err)
	}
	if _, err := client.Update(ctx, cos12); err != nil {
		t.Fatalf("client Update with threshold met: %v", err)
	}
}

func TestWitnessMergedCosignatures(t *testing.T) {
	op, opVerifier, _ := newTestLog(t)
	ctx := context.Background()

	w1, v1 := newTestWitness(t, "witness.one", opVerifier, op.Source())
	w2, v2 := newTestWitness(t, "witness.two", opVerifier, op.Source())
	policy2, err := NewPolicy(testOrigin, opVerifier, []note.Verifier{v1, v2}, 2)
	if err != nil {
		t.Fatal(err)
	}

	msg := appendAndPublish(t, op, 5)

	// Witnesses cosign independently (as they do over gossip); merging
	// their messages accumulates signatures toward the threshold.
	cos1, err := w1.Cosign(ctx, msg)
	if err != nil {
		t.Fatal(err)
	}
	cos2, err := w2.Cosign(ctx, msg)
	if err != nil {
		t.Fatal(err)
	}
	merged, err := mergeSignedNotes(cos1, cos2)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := policy2.Open(merged); err != nil {
		t.Fatalf("Open of merged cosignatures: %v", err)
	}
}

func TestWitnessConsistencyAndRollback(t *testing.T) {
	op, opVerifier, _ := newTestLog(t)
	ctx := context.Background()
	w, _ := newTestWitness(t, "witness.one", opVerifier, op.Source())

	msg5 := appendAndPublish(t, op, 5)
	if _, err := w.Cosign(ctx, msg5); err != nil {
		t.Fatal(err)
	}
	if head, ok := w.Head(); !ok || head.Tree.N != 5 {
		t.Fatalf("witness head = %+v %v, want size 5", head, ok)
	}

	msg12 := appendAndPublish(t, op, 12)
	if _, err := w.Cosign(ctx, msg12); err != nil {
		t.Fatalf("cosign with consistency proof: %v", err)
	}

	if _, err := w.Cosign(ctx, msg5); !errors.Is(err, ErrRollback) {
		t.Fatalf("cosign of old checkpoint = %v, want ErrRollback", err)
	}
}

func TestWitnessEquivocation(t *testing.T) {
	op, opVerifier, _ := newTestLog(t)
	ctx := context.Background()
	w, _ := newTestWitness(t, "witness.one", opVerifier, op.Source())

	twin, err := NewOperator(testOrigin, op.signer)
	if err != nil {
		t.Fatal(err)
	}
	msg := appendAndPublish(t, op, 8)
	for twin.Size() < 8 {
		if _, err := twin.Append(ctx, fmt.Appendf(nil, `{"twin":%d}`, twin.Size())); err != nil {
			t.Fatal(err)
		}
	}
	twinMsg, err := twin.Publish(ctx)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := w.Cosign(ctx, msg); err != nil {
		t.Fatal(err)
	}
	_, err = w.Cosign(ctx, twinMsg)
	var equiv *EquivocationError
	if !errors.As(err, &equiv) {
		t.Fatalf("cosign of split view = %v, want *EquivocationError", err)
	}
	if _, err := VerifyEquivocation(equiv.Proof, testOrigin, opVerifier); err != nil {
		t.Fatalf("equivocation proof does not verify: %v", err)
	}
}
