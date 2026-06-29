package contentdiscovery

import (
	"testing"
	"time"

	"github.com/tmc/go-iroh/blobs"
	"github.com/tmc/go-iroh/key"
)

func TestStorePutQueryDedup(t *testing.T) {
	store := NewStore(7 * 24 * time.Hour)
	sk := key.NewSecretKey([32]byte{1})
	content := blobs.RawHash(blobs.NewHash([]byte("content")))

	first := signedTestAnnounce(t, sk, content, AnnouncePartial, 10)
	second := signedTestAnnounce(t, sk, content, AnnouncePartial, 20)
	if err := store.PutAnnounce(first); err != nil {
		t.Fatalf("PutAnnounce first: %v", err)
	}
	if err := store.PutAnnounce(second); err != nil {
		t.Fatalf("PutAnnounce second: %v", err)
	}
	got, err := store.Query(Query{Content: content})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("Query returned %d announces, want 1", len(got))
	}
	if got[0].Announce.Timestamp != 20 {
		t.Fatalf("timestamp = %d, want 20", got[0].Announce.Timestamp)
	}
}

func TestStoreQueryPrefixAndFlags(t *testing.T) {
	store := NewStore(7 * 24 * time.Hour)
	sk1 := key.NewSecretKey([32]byte{1})
	sk2 := key.NewSecretKey([32]byte{2})
	content := blobs.RawHash(blobs.NewHash([]byte("content")))
	otherFormat := blobs.HashSeqHash(content.Hash)
	otherContent := blobs.RawHash(blobs.NewHash([]byte("other")))

	for _, sa := range []SignedAnnounce{
		signedTestAnnounce(t, sk1, content, AnnouncePartial, 10),
		signedTestAnnounce(t, sk2, content, AnnounceComplete, 11),
		signedTestAnnounce(t, sk1, otherFormat, AnnounceComplete, 12),
		signedTestAnnounce(t, sk1, otherContent, AnnounceComplete, 13),
	} {
		if err := store.PutAnnounce(sa); err != nil {
			t.Fatalf("PutAnnounce: %v", err)
		}
	}
	got, err := store.Query(Query{Content: content})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("Query returned %d announces, want 2", len(got))
	}
	got, err = store.Query(Query{Content: content, Flags: QueryFlags{Complete: true, Verified: true}})
	if err != nil {
		t.Fatalf("Query complete verified: %v", err)
	}
	if len(got) != 1 || got[0].Announce.Kind != AnnounceComplete {
		t.Fatalf("complete verified query = %+v, want one complete announce", got)
	}
}

func TestStoreGC(t *testing.T) {
	store := NewStore(time.Second)
	sk := key.NewSecretKey([32]byte{1})
	content := blobs.RawHash(blobs.NewHash([]byte("content")))
	old := signedTestAnnounce(t, sk, content, AnnouncePartial, 1)
	fresh := signedTestAnnounce(t, sk, content, AnnounceComplete, 2_500_000)
	if err := store.PutAnnounce(old); err != nil {
		t.Fatalf("PutAnnounce old: %v", err)
	}
	if err := store.PutAnnounce(fresh); err != nil {
		t.Fatalf("PutAnnounce fresh: %v", err)
	}
	if err := store.GC(3_000_000); err != nil {
		t.Fatalf("GC: %v", err)
	}
	got, err := store.Query(Query{Content: content})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(got) != 1 || got[0].Announce.Kind != AnnounceComplete {
		t.Fatalf("after GC = %+v, want fresh complete announce", got)
	}
}

func TestStoreKeyLayout(t *testing.T) {
	sk := key.NewSecretKey([32]byte{1})
	content := blobs.HashSeqHash(blobs.NewHash([]byte("content")))
	k, err := makeStoreKey(content, AnnounceComplete, sk.Public().EndpointID())
	if err != nil {
		t.Fatalf("makeStoreKey: %v", err)
	}
	b := k.bytes()
	hash := content.Hash.Bytes()
	host := sk.Public().EndpointID().Bytes()
	if got, want := b[:32], hash[:]; string(got) != string(want) {
		t.Fatal("key does not start with content hash")
	}
	if b[32] != byte(blobs.HashSeq) {
		t.Fatalf("format byte = %d, want %d", b[32], blobs.HashSeq)
	}
	if b[33] != byte(AnnounceComplete) {
		t.Fatalf("kind byte = %d, want %d", b[33], AnnounceComplete)
	}
	if got, want := b[34:], host[:]; string(got) != string(want) {
		t.Fatal("key does not end with host")
	}
}

func signedTestAnnounce(t *testing.T, sk key.SecretKey, content blobs.HashAndFormat, kind AnnounceKind, ts AbsoluteTime) SignedAnnounce {
	t.Helper()
	sa, err := SignAnnounce(sk, Announce{
		Host:      sk.Public().EndpointID(),
		Content:   content,
		Kind:      kind,
		Timestamp: ts,
	})
	if err != nil {
		t.Fatalf("SignAnnounce: %v", err)
	}
	return sa
}
