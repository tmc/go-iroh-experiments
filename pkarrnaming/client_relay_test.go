package pkarrnaming

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/tmc/go-iroh/blobs"
	"github.com/tmc/go-iroh/key"
)

func TestRelayClientRoundTrip(t *testing.T) {
	sk := key.NewSecretKey([32]byte{1})
	record := blobs.HashAndFormat{
		Hash:   blobs.NewHash([]byte("content")),
		Format: blobs.HashSeq,
	}
	relay := newMemoryRelay(t, false)
	client, err := NewRelayClient(relay.URL)
	if err != nil {
		t.Fatalf("NewRelayClient: %v", err)
	}

	if err := client.Publish(context.Background(), sk, record); err != nil {
		t.Fatalf("Publish: %v", err)
	}
	got, err := client.Resolve(context.Background(), sk.Public())
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if got != record {
		t.Fatalf("Resolve = %+v, want %+v", got, record)
	}
}

func TestRelayClientRejectsTamperedPayload(t *testing.T) {
	sk := key.NewSecretKey([32]byte{2})
	record := blobs.HashAndFormat{
		Hash:   blobs.NewHash([]byte("content")),
		Format: blobs.Raw,
	}
	relay := newMemoryRelay(t, true)
	client, err := NewRelayClient(relay.URL)
	if err != nil {
		t.Fatalf("NewRelayClient: %v", err)
	}

	if err := client.Publish(context.Background(), sk, record); err != nil {
		t.Fatalf("Publish: %v", err)
	}
	if _, err := client.Resolve(context.Background(), sk.Public()); err == nil {
		t.Fatal("Resolve succeeded with tampered payload")
	}
}

func TestRelayClientKeyURL(t *testing.T) {
	client, err := NewRelayClient("https://example.com/pkarr/")
	if err != nil {
		t.Fatalf("NewRelayClient: %v", err)
	}
	if got, want := client.keyURL("abc"), "https://example.com/pkarr/abc"; got != want {
		t.Fatalf("keyURL = %q, want %q", got, want)
	}
}

func newMemoryRelay(t *testing.T, tamper bool) *httptest.Server {
	t.Helper()
	var (
		mu      sync.Mutex
		payload = map[string][]byte{}
	)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPut:
			var b bytes.Buffer
			if _, err := b.ReadFrom(r.Body); err != nil {
				t.Errorf("read request body: %v", err)
				http.Error(w, "read body", http.StatusInternalServerError)
				return
			}
			mu.Lock()
			payload[r.URL.Path] = bytes.Clone(b.Bytes())
			mu.Unlock()
			w.WriteHeader(http.StatusNoContent)
		case http.MethodGet:
			mu.Lock()
			b, ok := payload[r.URL.Path]
			b = bytes.Clone(b)
			mu.Unlock()
			if !ok {
				http.NotFound(w, r)
				return
			}
			if tamper && len(b) > 0 {
				b[len(b)-1] ^= 1
			}
			_, _ = w.Write(b)
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	}))
	t.Cleanup(server.Close)
	return server
}
