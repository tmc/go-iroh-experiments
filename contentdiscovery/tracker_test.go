package contentdiscovery

import (
	"bytes"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/tmc/go-iroh/blobs"
	"github.com/tmc/go-iroh/key"
	"github.com/tmc/go-iroh/postcard"
)

func TestTrackerHandleRequest(t *testing.T) {
	store := NewStore(time.Hour)
	tracker := NewTrackerHandler(store)
	sk := key.NewSecretKey([32]byte{1})
	content := blobs.RawHash(blobs.NewHash([]byte("content")))
	announce := signedTestAnnounce(t, sk, content, AnnounceComplete, 1)

	announceReq, err := postcard.Marshal(Request{Kind: RequestAnnounce, Announce: announce})
	if err != nil {
		t.Fatalf("Marshal announce request: %v", err)
	}
	if _, err := tracker.HandleRequest(announceReq); err != nil {
		t.Fatalf("HandleRequest announce: %v", err)
	}

	queryReq, err := postcard.Marshal(Request{
		Kind:  RequestQuery,
		Query: Query{Content: content, Flags: QueryFlags{Complete: true, Verified: true}},
	})
	if err != nil {
		t.Fatalf("Marshal query request: %v", err)
	}
	respBytes, err := tracker.HandleRequest(queryReq)
	if err != nil {
		t.Fatalf("HandleRequest query: %v", err)
	}
	var resp Response
	if err := postcard.Unmarshal(respBytes, &resp); err != nil {
		t.Fatalf("Unmarshal response: %v", err)
	}
	if len(resp.QueryResponse.Hosts) != 1 || resp.QueryResponse.Hosts[0] != announce {
		t.Fatalf("query response = %+v, want one announced host", resp.QueryResponse.Hosts)
	}
}

func TestTrackerRejectsBadSignature(t *testing.T) {
	tracker := NewTrackerHandler(NewStore(time.Hour))
	sk := key.NewSecretKey([32]byte{1})
	content := blobs.RawHash(blobs.NewHash([]byte("content")))
	announce := signedTestAnnounce(t, sk, content, AnnounceComplete, 1)
	announce.Signature[0] ^= 1
	req, err := postcard.Marshal(Request{Kind: RequestAnnounce, Announce: announce})
	if err != nil {
		t.Fatalf("Marshal request: %v", err)
	}
	if _, err := tracker.HandleRequest(req); err == nil {
		t.Fatal("HandleRequest accepted bad signature")
	}
}

func TestReadLimited(t *testing.T) {
	if _, err := readLimited(strings.NewReader(strings.Repeat("x", RequestSizeLimit+1)), RequestSizeLimit); !errors.Is(err, errRequestTooLarge) {
		t.Fatalf("oversize err = %v, want %v", err, errRequestTooLarge)
	}
	got, err := readLimited(bytes.NewReader([]byte("ok")), RequestSizeLimit)
	if err != nil {
		t.Fatalf("readLimited: %v", err)
	}
	if string(got) != "ok" {
		t.Fatalf("readLimited = %q, want ok", got)
	}
}
