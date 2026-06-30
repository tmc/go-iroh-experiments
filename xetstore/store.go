package xetstore

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"

	"github.com/tmc/go-iroh/blobs"
	"lukechampine.com/blake3/bao"
)

const defaultEndpoint = "https://huggingface.co"

// Store is a blobs provider map backed by HuggingFace Xet resolve URLs.
//
// The zero Store is not usable; use New.
type Store struct {
	mu       sync.RWMutex
	entries  map[blobs.Hash]Entry
	client   *http.Client
	token    string
	endpoint string
}

// New returns an empty Store.
func New(opts ...Option) *Store {
	s := &Store{
		entries:  make(map[blobs.Hash]Entry),
		client:   http.DefaultClient,
		endpoint: defaultEndpoint,
	}
	for _, opt := range opts {
		opt(s)
	}
	if s.client == nil {
		s.client = http.DefaultClient
	}
	if s.endpoint == "" {
		s.endpoint = defaultEndpoint
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

// WithToken configures the HuggingFace bearer token.
func WithToken(token string) Option {
	return func(s *Store) {
		s.token = token
	}
}

// WithEndpoint configures the HuggingFace endpoint.
func WithEndpoint(baseURL string) Option {
	return func(s *Store) {
		s.endpoint = baseURL
	}
}

// File identifies one file inside a HuggingFace repository.
type File struct {
	Repo     string // "owner/model" or "datasets/owner/name"
	Revision string // default "main"
	Path     string // file path within the repo
}

// ImportFile imports f as a complete remote blob.
//
// ImportFile reads the file once to compute the root hash and outboard. If the
// Hub reports range support, future data reads use HTTP Range requests; otherwise
// the imported data is kept inline.
func (s *Store) ImportFile(ctx context.Context, f File) (blobs.Hash, error) {
	if s == nil {
		return blobs.Hash{}, errors.New("xetstore: nil store")
	}
	u, err := s.resolveURL(f)
	if err != nil {
		return blobs.Hash{}, err
	}
	size, ranged, err := s.probe(ctx, u)
	if err != nil {
		return blobs.Hash{}, err
	}
	data, err := s.getAll(ctx, u)
	if err != nil {
		return blobs.Hash{}, err
	}
	if size != 0 && size != uint64(len(data)) {
		return blobs.Hash{}, fmt.Errorf("xetstore: size mismatch: got %d, want %d", len(data), size)
	}
	var entry Entry
	if ranged {
		entry = newEntryFromRemote(u, data, s.client, s.token)
	} else {
		entry = newEntryFromBytes(data)
	}
	s.put(entry)
	return entry.hash, nil
}

// ImportBytes imports data as an inline complete blob.
func (s *Store) ImportBytes(data []byte) (blobs.Hash, error) {
	if s == nil {
		return blobs.Hash{}, errors.New("xetstore: nil store")
	}
	entry := newEntryFromBytes(data)
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

func (s *Store) resolveURL(f File) (string, error) {
	if f.Repo == "" {
		return "", errors.New("xetstore: empty repo")
	}
	if f.Path == "" {
		return "", errors.New("xetstore: empty path")
	}
	rev := f.Revision
	if rev == "" {
		rev = "main"
	}
	base, err := url.Parse(s.endpoint)
	if err != nil {
		return "", fmt.Errorf("xetstore: parse endpoint: %w", err)
	}
	if base.Scheme == "" || base.Host == "" {
		return "", errors.New("xetstore: endpoint must be absolute")
	}
	prefix := strings.TrimRight(base.Path, "/")
	parts := []string{strings.Trim(f.Repo, "/"), "resolve", rev, strings.TrimLeft(f.Path, "/")}
	segments := make([]string, 0, len(parts))
	for _, part := range parts {
		for _, segment := range strings.Split(part, "/") {
			if segment != "" {
				segments = append(segments, segment)
			}
		}
	}
	base.Path = prefix + "/" + strings.Join(segments, "/")
	base.RawPath = ""
	base.RawQuery = ""
	base.Fragment = ""
	return base.String(), nil
}

func (s *Store) probe(ctx context.Context, u string) (uint64, bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, u, nil)
	if err != nil {
		return 0, false, fmt.Errorf("xetstore: new head request: %w", err)
	}
	s.authorize(req)
	resp, err := s.client.Do(req)
	if err != nil {
		return 0, false, fmt.Errorf("xetstore: head file: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 0, false, fmt.Errorf("xetstore: head file: %s", resp.Status)
	}
	size, ok := responseSize(resp)
	ranged := strings.EqualFold(resp.Header.Get("Accept-Ranges"), "bytes")
	if ranged && !ok {
		size, ok = s.probeRangeSize(ctx, u)
	}
	return size, ranged && ok, nil
}

func (s *Store) probeRangeSize(ctx context.Context, u string) (uint64, bool) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return 0, false
	}
	s.authorize(req)
	req.Header.Set("Range", "bytes=0-0")
	resp, err := s.client.Do(req)
	if err != nil {
		return 0, false
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusPartialContent {
		return 0, false
	}
	return parseContentRangeSize(resp.Header.Get("Content-Range"))
}

func responseSize(resp *http.Response) (uint64, bool) {
	if v := resp.Header.Get("X-Linked-Size"); v != "" {
		n, err := strconv.ParseUint(v, 10, 64)
		return n, err == nil
	}
	if resp.ContentLength >= 0 {
		return uint64(resp.ContentLength), true
	}
	return 0, false
}

func parseContentRangeSize(v string) (uint64, bool) {
	_, after, ok := strings.Cut(v, "/")
	if !ok || after == "*" {
		return 0, false
	}
	n, err := strconv.ParseUint(after, 10, 64)
	return n, err == nil
}

func (s *Store) getAll(ctx context.Context, u string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, fmt.Errorf("xetstore: new get request: %w", err)
	}
	s.authorize(req)
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("xetstore: get file: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("xetstore: get file: %s", resp.Status)
	}
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("xetstore: read file: %w", err)
	}
	return data, nil
}

func (s *Store) authorize(req *http.Request) {
	if s.token != "" {
		req.Header.Set("Authorization", "Bearer "+s.token)
	}
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
	token  string
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

func newEntryFromRemote(u string, data []byte, client *http.Client, token string) Entry {
	outboard, root := bao.EncodeBuf(data, 4, true)
	return Entry{
		hash:     blobs.Hash(root),
		size:     uint64(len(data)),
		data:     dataSource{url: u, client: client, token: token},
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
	return httpReaderAt{url: e.data.url, size: e.size, client: client, token: e.data.token}, nil
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
	token  string
}

func (r httpReaderAt) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 {
		return 0, errors.New("xetstore: negative offset")
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
		return 0, fmt.Errorf("xetstore: new range request: %w", err)
	}
	if r.token != "" {
		req.Header.Set("Authorization", "Bearer "+r.token)
	}
	req.Header.Set("Range", fmt.Sprintf("bytes=%d-%d", start, end))
	resp, err := r.client.Do(req)
	if err != nil {
		return 0, fmt.Errorf("xetstore: range request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusPartialContent {
		return 0, fmt.Errorf("xetstore: range request: %s", resp.Status)
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
