package tlogiroh

import (
	"bytes"
	"context"
	"testing"
)

func TestEquivocationMarshalRoundTrip(t *testing.T) {
	want := Equivocation{First: []byte("first message"), Second: []byte("second message")}
	data, err := want.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	var got Equivocation
	if err := got.UnmarshalBinary(data); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got.First, want.First) || !bytes.Equal(got.Second, want.Second) {
		t.Fatalf("round trip = %+v, want %+v", got, want)
	}
}

func TestEquivocationUnmarshalErrors(t *testing.T) {
	for _, tt := range []struct {
		name string
		data []byte
	}{
		{"empty", nil},
		{"truncated first", []byte{10, 'a'}},
		{"missing second", []byte{1, 'a'}},
		{"trailing garbage", append([]byte{1, 'a', 1, 'b'}, 'x')},
	} {
		var e Equivocation
		if err := e.UnmarshalBinary(tt.data); err == nil {
			t.Errorf("%s: UnmarshalBinary succeeded, want error", tt.name)
		}
	}
}

func TestVerifyEquivocationRejects(t *testing.T) {
	op, verifier, _ := newTestLog(t)
	ctx := context.Background()

	msg5 := appendAndPublish(t, op, 5)
	msg9 := appendAndPublish(t, op, 9)

	if _, err := VerifyEquivocation(Equivocation{First: msg5, Second: msg9}, testOrigin, verifier); err == nil {
		t.Error("different sizes verified as equivocation")
	}
	if _, err := VerifyEquivocation(Equivocation{First: msg5, Second: msg5}, testOrigin, verifier); err == nil {
		t.Error("identical checkpoints verified as equivocation")
	}
	if _, err := VerifyEquivocation(Equivocation{First: msg5, Second: []byte("junk")}, testOrigin, verifier); err == nil {
		t.Error("junk second message verified as equivocation")
	}

	// A proof for another log's origin must not verify against this one.
	twin, err := NewOperator(testOrigin, op.signer)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := twin.Append(ctx, []byte("x")); err != nil {
		t.Fatal(err)
	}
	for twin.Size() < 5 {
		if _, err := twin.Append(ctx, []byte("y")); err != nil {
			t.Fatal(err)
		}
	}
	twinMsg, err := twin.Publish(ctx)
	if err != nil {
		t.Fatal(err)
	}
	proof := Equivocation{First: msg5, Second: twinMsg}
	if _, err := VerifyEquivocation(proof, "other.example.org/log", verifier); err == nil {
		t.Error("proof verified under the wrong origin")
	}
	if _, err := VerifyEquivocation(proof, testOrigin, verifier); err != nil {
		t.Errorf("genuine split view rejected: %v", err)
	}
}
