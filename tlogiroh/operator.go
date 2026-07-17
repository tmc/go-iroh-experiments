package tlogiroh

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/tmc/go-iroh/blobs"
	"github.com/tmc/go-iroh/docs"
	"github.com/tmc/go-iroh/gossip"
	"github.com/tmc/go-iroh/netaddr"
	"golang.org/x/mod/sumdb/note"
	"golang.org/x/mod/sumdb/tlog"
)

// An Operator is the single writer of a transparency log. It appends
// entries, stores entry and tile blobs, maintains the doc timeline, and
// signs checkpoints. Serve the log by registering the operator's blob store
// and doc store with the usual go-iroh protocol handlers; the operator
// itself performs no networking except Announce. An Operator is safe for
// concurrent use.
type Operator struct {
	origin string
	signer note.Signer

	mu         sync.Mutex
	blobMap    *blobs.BytesMap
	doc        *docs.MemoryStore
	namespace  docs.NamespaceSecret
	author     docs.Author
	hashes     []tlog.Hash // stored hashes, indexed by tlog.StoredHashIndex
	size       int64       // appended entries
	published  int64       // tree size covered by the latest checkpoint
	checkpoint []byte      // latest signed checkpoint note message
}

// NewOperator creates an empty log named origin, signing checkpoints with
// signer. origin must be non-empty and contain no newline.
func NewOperator(origin string, signer note.Signer) (*Operator, error) {
	if origin == "" || strings.Contains(origin, "\n") {
		return nil, fmt.Errorf("tlogiroh: invalid origin %q", origin)
	}
	if signer == nil {
		return nil, errors.New("tlogiroh: nil signer")
	}
	blobMap, err := blobs.NewBytesMap()
	if err != nil {
		return nil, fmt.Errorf("tlogiroh: new blob map: %w", err)
	}
	namespace, err := docs.GenerateNamespaceSecret()
	if err != nil {
		return nil, fmt.Errorf("tlogiroh: generate namespace: %w", err)
	}
	author, err := docs.GenerateAuthor()
	if err != nil {
		return nil, fmt.Errorf("tlogiroh: generate author: %w", err)
	}
	return &Operator{
		origin:    origin,
		signer:    signer,
		blobMap:   blobMap,
		doc:       docs.NewMemoryStore(),
		namespace: namespace,
		author:    author,
	}, nil
}

// Append adds entry to the log and returns its index. The entry is stored
// as a blob immediately; it is not part of a signed tree until the next
// Publish.
func (o *Operator) Append(ctx context.Context, entry []byte) (int64, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.append(entry)
}

// append is the regeneratable core of Append. It runs with o.mu held.
func (o *Operator) append(entry []byte) (int64, error) {
	index := o.size
	hashes, err := tlog.StoredHashes(index, entry, o.hashReader())
	if err != nil {
		return 0, fmt.Errorf("tlogiroh: append: %w", err)
	}
	blobHash, err := o.blobMap.Add(entry)
	if err != nil {
		return 0, fmt.Errorf("tlogiroh: append: %w", err)
	}
	o.hashes = append(o.hashes, hashes...)
	o.putTimeline(entryKey(index), blobHash, uint64(len(entry)))
	o.size++
	return index, nil
}

// Publish seals the appended entries into a new tree: it writes the new
// hash tiles as blobs, records tiles, entries, and the checkpoint in the
// doc timeline, and returns the signed checkpoint note message. Publish
// with no new entries re-signs and returns the current checkpoint.
func (o *Operator) Publish(ctx context.Context) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.publish()
}

// publish is the regeneratable core of Publish. It runs with o.mu held.
func (o *Operator) publish() ([]byte, error) {
	size := o.size
	for _, t := range tlog.NewTiles(TileHeight, o.published, size) {
		data, err := tlog.ReadTileData(t, o.hashReader())
		if err != nil {
			return nil, fmt.Errorf("tlogiroh: publish tile %s: %w", t.Path(), err)
		}
		blobHash, err := o.blobMap.Add(data)
		if err != nil {
			return nil, fmt.Errorf("tlogiroh: publish tile %s: %w", t.Path(), err)
		}
		o.putTimeline(tileKey(t), blobHash, uint64(len(data)))
	}
	root, err := tlog.TreeHash(size, o.hashReader())
	if err != nil {
		return nil, fmt.Errorf("tlogiroh: publish: %w", err)
	}
	text, err := Checkpoint{Origin: o.origin, Tree: tlog.Tree{N: size, Hash: root}}.MarshalText()
	if err != nil {
		return nil, err
	}
	msg, err := note.Sign(&note.Note{Text: string(text)}, o.signer)
	if err != nil {
		return nil, fmt.Errorf("tlogiroh: sign checkpoint: %w", err)
	}
	blobHash, err := o.blobMap.Add(msg)
	if err != nil {
		return nil, fmt.Errorf("tlogiroh: publish checkpoint: %w", err)
	}
	o.putTimeline(checkpointKey(size), blobHash, uint64(len(msg)))
	o.published = size
	o.checkpoint = msg
	return msg, nil
}

// Announce broadcasts the latest signed checkpoint on the gossip topic.
// It returns ErrNoCheckpoint before the first Publish.
func (o *Operator) Announce(ctx context.Context, topic *gossip.Topic) error {
	msg := o.SignedCheckpoint()
	if msg == nil {
		return ErrNoCheckpoint
	}
	return topic.Broadcast(ctx, envelope(envCheckpoint, msg))
}

// Size returns the number of appended entries, including entries not yet
// covered by a published checkpoint.
func (o *Operator) Size() int64 {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.size
}

// SignedCheckpoint returns the latest signed checkpoint note message, or
// nil before the first Publish.
func (o *Operator) SignedCheckpoint() []byte {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.checkpoint
}

// Blobs returns the operator's blob store holding entries, tiles, and
// checkpoint notes, for serving with the iroh blobs protocol.
func (o *Operator) Blobs() blobs.Store {
	return o.blobMap.Store()
}

// Doc returns the operator's doc store holding the log timeline, for
// serving with the iroh docs sync protocol.
func (o *Operator) Doc() *docs.MemoryStore {
	return o.doc
}

// Namespace returns the doc namespace the timeline is written in.
func (o *Operator) Namespace() docs.NamespaceID {
	return o.namespace.ID()
}

// Author returns the doc author id the operator writes with.
func (o *Operator) Author() docs.AuthorID {
	return o.author.ID()
}

// Source returns a Source reading directly from the operator's own stores,
// for colocated readers and tests.
func (o *Operator) Source() Source {
	return Source{
		Doc:       o.doc,
		Namespace: o.namespace.ID(),
		Author:    o.author.ID(),
		Get:       StoreBlobGetter(o.blobMap.Store()),
	}
}

// Ticket returns a read-capability doc ticket for the log timeline, listing
// addrs as sync peers.
func (o *Operator) Ticket(addrs []netaddr.EndpointAddr) docs.DocTicket {
	return docs.NewTicket(docs.NewReadCapability(o.namespace.ID()), addrs)
}

// putTimeline writes one timeline entry mapping key to a stored blob.
// It runs with o.mu held.
func (o *Operator) putTimeline(key string, blobHash blobs.Hash, length uint64) {
	id := docs.NewRecordIdentifier(o.namespace.ID(), o.author.ID(), []byte(key))
	record := docs.NewRecord(blobHash, length, uint64(time.Now().UnixMicro()))
	o.doc.Put(docs.NewSignedEntry(docs.NewEntry(id, record), o.namespace, o.author))
}

// hashReader reads the operator's own stored hashes. It runs with o.mu held.
func (o *Operator) hashReader() tlog.HashReader {
	return tlog.HashReaderFunc(func(indexes []int64) ([]tlog.Hash, error) {
		hashes := make([]tlog.Hash, len(indexes))
		for i, index := range indexes {
			if index < 0 || index >= int64(len(o.hashes)) {
				return nil, fmt.Errorf("tlogiroh: stored hash index %d out of range", index)
			}
			hashes[i] = o.hashes[index]
		}
		return hashes, nil
	})
}
