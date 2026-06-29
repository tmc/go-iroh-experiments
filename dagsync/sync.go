package dagsync

import (
	"context"
	"errors"
	"fmt"
	"io"

	"github.com/ipfs/go-cid"
	"github.com/tmc/go-iroh/blobs"
	"github.com/tmc/go-iroh/iroh"
	"github.com/tmc/go-iroh/netaddr"
)

const maxRequestSize = 16 * 1024 * 1024

// Handler serves dagsync requests.
type Handler struct {
	Tables *Tables
	Blobs  blobs.Map
}

// Accept implements iroh.ProtocolHandler.
func (h *Handler) Accept(ctx context.Context, conn *iroh.Conn) error {
	s, err := conn.AcceptStream(ctx)
	if err != nil {
		return err
	}
	defer s.Close()
	return h.HandleStream(ctx, s)
}

// HandleStream serves one bidirectional stream.
func (h *Handler) HandleStream(ctx context.Context, rw io.ReadWriter) error {
	if h.Tables == nil {
		return errors.New("dagsync: nil tables")
	}
	if h.Blobs == nil {
		return errors.New("dagsync: nil blob map")
	}
	reqBytes, err := io.ReadAll(io.LimitReader(rw, maxRequestSize+1))
	if err != nil {
		return err
	}
	if len(reqBytes) > maxRequestSize {
		return errors.New("dagsync: request too large")
	}
	var req Request
	if err := decodePostcard(reqBytes, &req); err != nil {
		return err
	}
	if req.Sync == nil {
		return errors.New("dagsync: non-sync request")
	}
	return WriteSyncResponse(ctx, rw, *req.Sync, h.Tables, h.Blobs)
}

// WriteSyncResponse writes the response for req.
func WriteSyncResponse(ctx context.Context, w io.Writer, req SyncRequest, tables *Tables, m blobs.Map) error {
	cids, err := traversalCIDs(req.Traversal, tables)
	if err != nil {
		return err
	}
	inline := inlinePredicate(req.Inline)
	for _, c := range cids {
		if err := ctxErr(ctx); err != nil {
			return err
		}
		hash, ok := tables.BlobHash(c)
		if !ok {
			return fmt.Errorf("dagsync: blob hash not found for %s", c)
		}
		if inline(c) {
			if err := writeHeader(w, DataHeader(hash)); err != nil {
				return err
			}
			entry, ok, err := m.Get(ctx, hash)
			if err != nil {
				return err
			}
			if !ok {
				return fmt.Errorf("dagsync: blob data not found for %s", hash)
			}
			data, err := readEntry(ctx, entry)
			if err != nil {
				return err
			}
			got, enc, err := blobs.EncodeBlob(data)
			if err != nil {
				return err
			}
			if got != hash {
				return fmt.Errorf("dagsync: blob hash mismatch for %s", hash)
			}
			if _, err := w.Write(enc); err != nil {
				return err
			}
		} else if err := writeHeader(w, HashHeader(hash)); err != nil {
			return err
		}
	}
	return nil
}

// Sync requests data from addr and imports inline response data into out.
func Sync(ctx context.Context, ep *iroh.Endpoint, addr netaddr.EndpointAddr, tables *Tables, out *blobs.BytesMap, req SyncRequest) error {
	conn, err := ep.Connect(ctx, addr, ALPN)
	if err != nil {
		return err
	}
	defer conn.CloseWithError(0, "")
	s, err := conn.OpenStreamSync(ctx)
	if err != nil {
		return err
	}
	defer s.Close()
	request := NewSyncRequest(req.Traversal, req.Inline)
	b, err := encodePostcard(request)
	if err != nil {
		return err
	}
	if _, err := s.Write(b); err != nil {
		return err
	}
	if err := s.Close(); err != nil {
		return err
	}
	return ReadSyncResponse(ctx, s, tables, out, req.Traversal)
}

// ReadSyncResponse reads a sync response and records inline data.
func ReadSyncResponse(ctx context.Context, r io.Reader, tables *Tables, out *blobs.BytesMap, traversal TraversalOpts) error {
	if traversal.Full != nil {
		return readFullSyncResponse(ctx, r, tables, out, traversal.Full)
	}
	cids, err := traversalCIDs(traversal, tables)
	if err != nil {
		return err
	}
	for _, c := range cids {
		if err := readOneResponse(ctx, r, tables, out, c); err != nil {
			return err
		}
	}
	return nil
}

func readFullSyncResponse(ctx context.Context, r io.Reader, tables *Tables, out *blobs.BytesMap, opts *FullTraversalOpts) error {
	filter := TraversalFilter{All: true}
	if opts.Filter != nil {
		filter = *opts.Filter
	}
	visited := make(map[string]bool)
	for _, c := range opts.Visited {
		visited[c.Cid.KeyString()] = true
	}
	stack := []cid.Cid{opts.Root.Cid}
	for len(stack) > 0 {
		c := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if visited[c.KeyString()] {
			continue
		}
		visited[c.KeyString()] = true
		if includeCID(filter, c) {
			if err := readOneResponse(ctx, r, tables, out, c); err != nil {
				return err
			}
		}
		if c.Type() == cid.Raw {
			continue
		}
		links, ok := tables.Links(c)
		if !ok {
			continue
		}
		for i := len(links) - 1; i >= 0; i-- {
			stack = append(stack, links[i])
		}
	}
	return nil
}

func readOneResponse(ctx context.Context, r io.Reader, tables *Tables, out *blobs.BytesMap, c cid.Cid) error {
	if err := ctxErr(ctx); err != nil {
		return err
	}
	header, err := readHeader(r)
	if errors.Is(err, io.EOF) {
		return nil
	}
	if err != nil {
		return err
	}
	if header.Hash != nil {
		tables.Put(c, *header.Hash, nil)
		return nil
	}
	if header.Data == nil {
		return errors.New("dagsync: empty response header")
	}
	data, err := blobs.DecodeBlobReader(*header.Data, r)
	if err != nil {
		return err
	}
	if err := cidMatchesData(c, data); err != nil {
		return err
	}
	hash, err := out.Add(data)
	if err != nil {
		return err
	}
	if hash != *header.Data {
		return errors.New("dagsync: imported hash mismatch")
	}
	links, err := ExtractLinks(c, data)
	if err != nil {
		return err
	}
	tables.Put(c, hash, links)
	return nil
}

func writeHeader(w io.Writer, h SyncResponseHeader) error {
	b, err := h.Bytes()
	if err != nil {
		return err
	}
	_, err = w.Write(b[:])
	return err
}

func readHeader(r io.Reader) (SyncResponseHeader, error) {
	var b [33]byte
	_, err := io.ReadFull(r, b[:])
	if err != nil {
		return SyncResponseHeader{}, err
	}
	return decodeHeader(b[:])
}

func readEntry(ctx context.Context, entry blobs.MapEntry) ([]byte, error) {
	if !entry.IsComplete() {
		return nil, errors.New("dagsync: incomplete blob entry")
	}
	size, ok := entry.Size()
	if !ok {
		return nil, errors.New("dagsync: unverified blob size")
	}
	r, err := entry.DataReader(ctx)
	if err != nil {
		return nil, err
	}
	data := make([]byte, size)
	if _, err := r.ReadAt(data, 0); err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	return data, nil
}

func ctxErr(ctx context.Context) error {
	if ctx == nil {
		return nil
	}
	return ctx.Err()
}

func _cid(c cid.Cid) cid.Cid { return c }
