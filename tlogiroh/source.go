package tlogiroh

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"github.com/tmc/go-iroh/blobs"
	"github.com/tmc/go-iroh/docs"
	"github.com/tmc/go-iroh/iroh"
	"github.com/tmc/go-iroh/netaddr"
	"golang.org/x/mod/sumdb/tlog"
)

// A BlobGetter fetches the content of one blob by hash. Implementations
// must return the full verified blob bytes or an error.
type BlobGetter func(ctx context.Context, hash blobs.Hash) ([]byte, error)

// StoreBlobGetter returns a BlobGetter reading from a local blob store.
func StoreBlobGetter(store blobs.Store) BlobGetter {
	return func(_ context.Context, hash blobs.Hash) ([]byte, error) {
		data, ok := store.GetBlob(hash)
		if !ok {
			return nil, fmt.Errorf("tlogiroh: get blob %v: %w", hash, blobs.ErrBlobNotFound)
		}
		return data, nil
	}
}

// DialBlobGetter returns a BlobGetter that fetches blobs from the peer at
// addr over the iroh blobs protocol, dialing on first use.
func DialBlobGetter(ep *iroh.Endpoint, addr netaddr.EndpointAddr) BlobGetter {
	var mu sync.Mutex
	var conn *iroh.Conn
	return func(ctx context.Context, hash blobs.Hash) ([]byte, error) {
		mu.Lock()
		if conn == nil {
			c, err := ep.Connect(ctx, addr, blobs.ALPN)
			if err != nil {
				mu.Unlock()
				return nil, fmt.Errorf("tlogiroh: dial blob provider: %w", err)
			}
			conn = c
		}
		c := conn
		mu.Unlock()
		s, err := c.OpenStreamSync(ctx)
		if err != nil {
			return nil, fmt.Errorf("tlogiroh: open blob stream: %w", err)
		}
		data, err := blobs.GetBlobBytes(ctx, s, hash)
		if err != nil {
			return nil, fmt.Errorf("tlogiroh: get blob %v: %w", hash, err)
		}
		return data, nil
	}
}

// A Source is where a client or witness reads a log from: a synced doc
// replica for the index and a BlobGetter for content. Keeping the doc
// replica fresh (docs.Sync, docs.SyncTicket, docs.LiveSync) is the caller's
// concern.
type Source struct {
	Doc       *docs.MemoryStore // synced replica of the log timeline
	Namespace docs.NamespaceID  // the timeline namespace
	Author    docs.AuthorID     // the operator's author id
	Get       BlobGetter        // fetches tile, entry, and checkpoint blobs
}

// Doc timeline key forms. See the package documentation.
const (
	entryKeyPrefix      = "entry/"
	checkpointKeyPrefix = "checkpoint/"
)

func entryKey(index int64) string {
	return fmt.Sprintf("%s%020d", entryKeyPrefix, index)
}

func checkpointKey(size int64) string {
	return fmt.Sprintf("%s%020d", checkpointKeyPrefix, size)
}

// tileKey returns the timeline key for a tile: the coordinate path of the
// complete tile plus an explicit zero-padded width suffix. The suffix keeps
// every published width under its own key and makes tile keys prefix-free:
// iroh-docs inserts delete older entries whose keys extend the new key, so
// keying a complete tile by its bare path would erase the partial widths
// that older checkpoints still need for proofs.
func tileKey(t tlog.Tile) string {
	complete := tlog.Tile{H: t.H, L: t.L, N: t.N, W: 1 << t.H}
	return fmt.Sprintf("%s.w/%03d", complete.Path(), t.W)
}

// blob resolves a timeline key to its record and fetches the blob content.
func (s Source) blob(ctx context.Context, key string) ([]byte, error) {
	entry, ok := s.Doc.GetExact(s.Namespace, s.Author, []byte(key), false)
	if !ok {
		return nil, fmt.Errorf("tlogiroh: no timeline entry for %q", key)
	}
	data, err := s.Get(ctx, entry.Entry.Record.Hash)
	if err != nil {
		return nil, err
	}
	if uint64(len(data)) != entry.Entry.Record.Len {
		return nil, fmt.Errorf("tlogiroh: blob for %q is %d bytes, timeline records %d", key, len(data), entry.Entry.Record.Len)
	}
	return data, nil
}

// latestCheckpoint returns the signed checkpoint note with the largest tree
// size recorded in the timeline. It returns ErrNoCheckpoint if none exists.
func (s Source) latestCheckpoint(ctx context.Context) ([]byte, error) {
	var latest string
	for _, entry := range s.Doc.Entries() {
		if entry.Entry.Namespace() != s.Namespace || entry.Entry.Author() != s.Author {
			continue
		}
		key := string(entry.Entry.Key())
		if !strings.HasPrefix(key, checkpointKeyPrefix) {
			continue
		}
		if key > latest {
			latest = key
		}
	}
	if latest == "" {
		return nil, ErrNoCheckpoint
	}
	return s.blob(ctx, latest)
}

// tileReader adapts a Source to tlog.TileReader for one verification pass.
// Tiles are content-addressed blobs, so SaveTiles has nothing to do; the
// authenticity check happens in tlog.TileHashReader against the tree hash.
//
// The exact-width check in ReadTiles is sound because tileKey encodes the
// width, so every published width keeps its own timeline key and is never
// shadowed by a wider revision; the TileReader contract requires the
// returned data to match the requested width exactly.
type tileReader struct {
	ctx context.Context
	src Source
}

func (r tileReader) Height() int { return TileHeight }

func (r tileReader) ReadTiles(tiles []tlog.Tile) ([][]byte, error) {
	data := make([][]byte, len(tiles))
	for i, t := range tiles {
		b, err := r.src.blob(r.ctx, tileKey(t))
		if err != nil {
			return nil, err
		}
		if len(b) != t.W*tlog.HashSize {
			return nil, fmt.Errorf("tlogiroh: tile %s is %d bytes, want %d", t.Path(), len(b), t.W*tlog.HashSize)
		}
		data[i] = b
	}
	return data, nil
}

func (r tileReader) SaveTiles(tiles []tlog.Tile, data [][]byte) {}

// hashReaderForTree returns a HashReader whose hashes are authenticated
// against tree via the source's tiles.
func (s Source) hashReaderForTree(ctx context.Context, tree tlog.Tree) tlog.HashReader {
	return tlog.TileHashReader(tree, tileReader{ctx: ctx, src: s})
}
