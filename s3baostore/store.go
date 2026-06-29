package s3baostore

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sync"

	"github.com/tmc/go-iroh/blobs"
	"lukechampine.com/blake3/bao"
)

// Store is a blobs provider map backed by inline data or HTTP/S3 objects.
type Store struct {
	mu      sync.RWMutex
	entries map[blobs.Hash]Entry
	client  *http.Client
}

// New returns an empty Store.
func New(opts ...Option) *Store {
	s := &Store{
		entries: make(map[blobs.Hash]Entry),
		client:  http.DefaultClient,
	}
	for _, opt := range opts {
		opt(s)
	}
	if s.client == nil {
		s.client = http.DefaultClient
	}
	return s
}

// Option configures a Store.
type Option func(*Store)

// WithHTTPClient configures the HTTP client used for imports and range reads.
func WithHTTPClient(c *http.Client) Option {
	return func(s *Store) {
		s.client = c
	}
}

// ImportBytes imports data as an inline complete blob.
func (s *Store) ImportBytes(data []byte) (blobs.Hash, error) {
	entry := newEntryFromBytes(data)
	s.put(entry)
	return entry.hash, nil
}

// ImportURL imports u as a complete remote blob.
//
// ImportURL reads the object once to compute the root hash and outboard, then
// stores only the URL and outboard. Future data reads use HTTP Range requests.
func (s *Store) ImportURL(ctx context.Context, u string) (blobs.Hash, error) {
	parsed, err := url.Parse(u)
	if err != nil {
		return blobs.Hash{}, fmt.Errorf("s3baostore: parse url: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, parsed.String(), nil)
	if err != nil {
		return blobs.Hash{}, fmt.Errorf("s3baostore: new request: %w", err)
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return blobs.Hash{}, fmt.Errorf("s3baostore: get url: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return blobs.Hash{}, fmt.Errorf("s3baostore: get url: %s", resp.Status)
	}
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return blobs.Hash{}, fmt.Errorf("s3baostore: read url: %w", err)
	}
	entry := newEntryFromRemote(parsed.String(), data, s.client)
	s.put(entry)
	return entry.hash, nil
}

// Get returns the entry for hash.
func (s *Store) Get(ctx context.Context, hash blobs.Hash) (blobs.MapEntry, bool, error) {
	if ctx != nil {
		if err := ctx.Err(); err != nil {
			return nil, false, err
		}
	}
	if s == nil {
		return nil, false, nil
	}
	s.mu.RLock()
	entry, ok := s.entries[hash]
	s.mu.RUnlock()
	if !ok {
		return nil, false, nil
	}
	return entry, true, nil
}

func (s *Store) put(entry Entry) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.entries == nil {
		s.entries = make(map[blobs.Hash]Entry)
	}
	s.entries[entry.hash] = entry
}

// Entry is one complete blob entry.
type Entry struct {
	hash     blobs.Hash
	size     uint64
	data     dataSource
	outboard []byte
}

type dataSource struct {
	inline []byte
	url    string
	client *http.Client
}

func newEntryFromBytes(data []byte) Entry {
	outboard, root := bao.EncodeBuf(data, 4, true)
	return Entry{
		hash:     blobs.Hash(root),
		size:     uint64(len(data)),
		data:     dataSource{inline: append([]byte(nil), data...)},
		outboard: outboard,
	}
}

func newEntryFromRemote(u string, data []byte, client *http.Client) Entry {
	outboard, root := bao.EncodeBuf(data, 4, true)
	return Entry{
		hash:     blobs.Hash(root),
		size:     uint64(len(data)),
		data:     dataSource{url: u, client: client},
		outboard: outboard,
	}
}

// Hash returns e's root hash.
func (e Entry) Hash() blobs.Hash { return e.hash }

// Size returns e's verified object size.
func (e Entry) Size() (uint64, bool) { return e.size, true }

// IsComplete reports whether e has complete verified metadata.
func (e Entry) IsComplete() bool { return true }

// DataReader returns a reader for e's data.
func (e Entry) DataReader(ctx context.Context) (io.ReaderAt, error) {
	if ctx != nil {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
	}
	if e.data.url == "" {
		return bytes.NewReader(e.data.inline), nil
	}
	client := e.data.client
	if client == nil {
		client = http.DefaultClient
	}
	return httpReaderAt{url: e.data.url, size: e.size, client: client}, nil
}

// Outboard returns e's in-memory BAO outboard.
func (e Entry) Outboard(ctx context.Context) (blobs.Outboard, error) {
	if ctx != nil {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
	}
	return byteOutboard{Reader: bytes.NewReader(e.outboard), size: int64(len(e.outboard))}, nil
}

type byteOutboard struct {
	*bytes.Reader
	size int64
}

func (o byteOutboard) Size() int64 { return o.size }

type httpReaderAt struct {
	url    string
	size   uint64
	client *http.Client
}

func (r httpReaderAt) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 {
		return 0, errors.New("s3baostore: negative offset")
	}
	if len(p) == 0 {
		return 0, nil
	}
	start := uint64(off)
	if start >= r.size {
		return 0, io.EOF
	}
	end := start + uint64(len(p)) - 1
	if end >= r.size {
		end = r.size - 1
	}
	req, err := http.NewRequest(http.MethodGet, r.url, nil)
	if err != nil {
		return 0, fmt.Errorf("s3baostore: new range request: %w", err)
	}
	req.Header.Set("Range", fmt.Sprintf("bytes=%d-%d", start, end))
	resp, err := r.client.Do(req)
	if err != nil {
		return 0, fmt.Errorf("s3baostore: range request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusPartialContent {
		return 0, fmt.Errorf("s3baostore: range request: %s", resp.Status)
	}
	n, err := io.ReadFull(resp.Body, p[:end-start+1])
	if err != nil {
		return n, err
	}
	if n < len(p) {
		return n, io.EOF
	}
	return n, nil
}
