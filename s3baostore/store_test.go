package s3baostore

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/tmc/go-iroh/blobs"
	"lukechampine.com/blake3/bao"
)

func TestImportBytes(t *testing.T) {
	data := []byte("inline object")
	store := New()
	hash, err := store.ImportBytes(data)
	if err != nil {
		t.Fatalf("ImportBytes: %v", err)
	}
	entry, ok, err := store.Get(context.Background(), hash)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !ok {
		t.Fatal("Get = false, want true")
	}
	assertEntry(t, entry, data)
}

func TestImportURLKeepsDataRemote(t *testing.T) {
	data := bytes.Repeat([]byte("remote"), 4000)
	var fullGets, rangeGets int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Header.Get("Range") {
		case "":
			fullGets++
			w.Write(data)
		case "bytes=3-9":
			rangeGets++
			w.Header().Set("Content-Range", "bytes 3-9/24000")
			w.WriteHeader(http.StatusPartialContent)
			w.Write(data[3:10])
		default:
			t.Fatalf("unexpected range %q", r.Header.Get("Range"))
		}
	}))
	defer srv.Close()

	store := New(WithHTTPClient(srv.Client()))
	hash, err := store.ImportURL(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("ImportURL: %v", err)
	}
	if fullGets != 1 {
		t.Fatalf("full GETs = %d, want 1", fullGets)
	}
	entry, ok, err := store.Get(context.Background(), hash)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !ok {
		t.Fatal("Get = false, want true")
	}
	if got := entry.Hash(); got != blobs.NewHash(data) {
		t.Fatalf("Hash = %s, want %s", got, blobs.NewHash(data))
	}
	outboard, err := entry.Outboard(context.Background())
	if err != nil {
		t.Fatalf("Outboard: %v", err)
	}
	out := make([]byte, outboard.Size())
	if _, err := outboard.ReadAt(out, 0); err != nil && err != io.EOF {
		t.Fatalf("ReadAt outboard: %v", err)
	}
	if !bao.VerifyBuf(data, out, 4, hash.Bytes()) {
		t.Fatal("outboard does not verify remote data")
	}

	r, err := entry.DataReader(context.Background())
	if err != nil {
		t.Fatalf("DataReader: %v", err)
	}
	buf := make([]byte, 7)
	if _, err := r.ReadAt(buf, 3); err != nil {
		t.Fatalf("ReadAt: %v", err)
	}
	if !bytes.Equal(buf, data[3:10]) {
		t.Fatalf("range read = %q, want %q", buf, data[3:10])
	}
	if rangeGets != 1 {
		t.Fatalf("range GETs = %d, want 1", rangeGets)
	}
}

func assertEntry(t *testing.T, entry blobs.MapEntry, data []byte) {
	t.Helper()
	if got := entry.Hash(); got != blobs.NewHash(data) {
		t.Fatalf("Hash = %s, want %s", got, blobs.NewHash(data))
	}
	if size, verified := entry.Size(); size != uint64(len(data)) || !verified {
		t.Fatalf("Size = %d, %v, want %d, true", size, verified, len(data))
	}
	r, err := entry.DataReader(context.Background())
	if err != nil {
		t.Fatalf("DataReader: %v", err)
	}
	got := make([]byte, len(data))
	if _, err := r.ReadAt(got, 0); err != nil && err != io.EOF {
		t.Fatalf("ReadAt: %v", err)
	}
	if !bytes.Equal(got, data) {
		t.Fatalf("data = %q, want %q", got, data)
	}
}
