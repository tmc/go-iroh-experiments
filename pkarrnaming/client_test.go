package pkarrnaming

import (
	"context"
	"testing"

	"github.com/tmc/go-iroh/blobs"
	"github.com/tmc/go-iroh/key"
)

type fakeClient struct {
	published blobs.HashAndFormat
	resolved  blobs.HashAndFormat
}

func (f *fakeClient) Publish(ctx context.Context, sk key.SecretKey, r blobs.HashAndFormat) error {
	f.published = r
	return nil
}

func (f *fakeClient) Resolve(ctx context.Context, pk key.PublicKey) (blobs.HashAndFormat, error) {
	return f.resolved, nil
}

func TestPublisherResolver(t *testing.T) {
	ctx := context.Background()
	sk := key.NewSecretKey([32]byte{1})
	want := blobs.HashSeqHash(blobs.NewHash([]byte("content")))
	f := &fakeClient{resolved: want}

	if err := NewPublisher(f).Publish(ctx, sk, want); err != nil {
		t.Fatalf("Publish: %v", err)
	}
	if f.published != want {
		t.Fatalf("published = %+v, want %+v", f.published, want)
	}
	got, err := NewResolver(f).Resolve(ctx, sk.Public())
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if got != want {
		t.Fatalf("Resolve = %+v, want %+v", got, want)
	}
}
