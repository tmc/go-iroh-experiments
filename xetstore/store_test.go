package xetstore

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/tmc/go-iroh/blobs"
	"lukechampine.com/blake3/bao"
)

func TestImportBytes(t *testing.T) {
	data := []byte("inline xet object")
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

func TestImportFileKeepsDataRemote(t *testing.T) {
	data := bytes.Repeat([]byte("xet-remote"), 3000)
	var fullGets, rangeGets int
	var sawHeadAuth, sawGetAuth, sawRangeAuth bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/owner/model/resolve/rev/weights/model.bin" {
			t.Fatalf("path = %q, want resolve path", r.URL.Path)
		}
		if r.Header.Get("Authorization") == "Bearer hf_test" {
			switch r.Method {
			case http.MethodHead:
				sawHeadAuth = true
			case http.MethodGet:
				if r.Header.Get("Range") == "" {
					sawGetAuth = true
				} else {
					sawRangeAuth = true
				}
			}
		}
		switch {
		case r.Method == http.MethodHead:
			w.Header().Set("Accept-Ranges", "bytes")
			w.Header().Set("X-Linked-Size", fmt.Sprint(len(data)))
		case r.Method == http.MethodGet && r.Header.Get("Range") == "":
			fullGets++
			w.Write(data)
		case r.Method == http.MethodGet && r.Header.Get("Range") == "bytes=5-16":
			rangeGets++
			w.Header().Set("Content-Range", fmt.Sprintf("bytes 5-16/%d", len(data)))
			w.WriteHeader(http.StatusPartialContent)
			w.Write(data[5:17])
		default:
			t.Fatalf("unexpected %s range %q", r.Method, r.Header.Get("Range"))
		}
	}))
	defer srv.Close()

	store := New(WithHTTPClient(srv.Client()), WithEndpoint(srv.URL), WithToken("hf_test"))
	hash, err := store.ImportFile(context.Background(), File{
		Repo:     "owner/model",
		Revision: "rev",
		Path:     "weights/model.bin",
	})
	if err != nil {
		t.Fatalf("ImportFile: %v", err)
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
	buf := make([]byte, 12)
	if _, err := r.ReadAt(buf, 5); err != nil {
		t.Fatalf("ReadAt: %v", err)
	}
	if !bytes.Equal(buf, data[5:17]) {
		t.Fatalf("range read = %q, want %q", buf, data[5:17])
	}
	if rangeGets != 1 {
		t.Fatalf("range GETs = %d, want 1", rangeGets)
	}
	if !sawHeadAuth || !sawGetAuth || !sawRangeAuth {
		t.Fatalf("auth head/get/range = %v/%v/%v, want all true", sawHeadAuth, sawGetAuth, sawRangeAuth)
	}
}

func TestImportFileFallsBackInlineWithoutRanges(t *testing.T) {
	data := []byte("inline fallback")
	var rangeGets int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodHead:
			w.Header().Set("Content-Length", fmt.Sprint(len(data)))
		case r.Method == http.MethodGet && r.Header.Get("Range") == "":
			w.Write(data)
		case r.Header.Get("Range") != "":
			rangeGets++
			t.Fatalf("unexpected range read for inline fallback")
		}
	}))
	defer srv.Close()

	store := New(WithHTTPClient(srv.Client()), WithEndpoint(srv.URL))
	hash, err := store.ImportFile(context.Background(), File{Repo: "datasets/owner/name", Path: "data.bin"})
	if err != nil {
		t.Fatalf("ImportFile: %v", err)
	}
	entry, ok, err := store.Get(context.Background(), hash)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !ok {
		t.Fatal("Get = false, want true")
	}
	assertEntry(t, entry, data)
	if rangeGets != 0 {
		t.Fatalf("range GETs = %d, want 0", rangeGets)
	}
}

func TestImportFileHeadError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	defer srv.Close()

	store := New(WithHTTPClient(srv.Client()), WithEndpoint(srv.URL))
	_, err := store.ImportFile(context.Background(), File{Repo: "owner/model", Path: "missing.bin"})
	if err == nil {
		t.Fatal("ImportFile err = nil, want error")
	}
	if !strings.Contains(err.Error(), "xetstore: head file: 404 Not Found") {
		t.Fatalf("ImportFile err = %v, want wrapped head status", err)
	}
}

func TestResolveURLDefaultsRevision(t *testing.T) {
	store := New(WithEndpoint("https://huggingface.co/base/"))
	got, err := store.resolveURL(File{Repo: "datasets/owner/name", Path: "a b/file.bin"})
	if err != nil {
		t.Fatalf("resolveURL: %v", err)
	}
	want := "https://huggingface.co/base/datasets/owner/name/resolve/main/a%20b/file.bin"
	if got != want {
		t.Fatalf("resolveURL = %q, want %q", got, want)
	}
}

func TestReadAtNegativeOffset(t *testing.T) {
	_, err := httpReaderAt{size: 1, client: http.DefaultClient}.ReadAt(make([]byte, 1), -1)
	if err == nil || err.Error() != "xetstore: negative offset" {
		t.Fatalf("ReadAt negative offset err = %v", err)
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
