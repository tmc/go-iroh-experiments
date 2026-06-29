package dagsync

import (
	"bytes"
	"context"
	"fmt"
	"sync"

	"github.com/ipfs/go-cid"
	"github.com/ipld/go-ipld-prime/codec/dagcbor"
	"github.com/ipld/go-ipld-prime/datamodel"
	cidlink "github.com/ipld/go-ipld-prime/linking/cid"
	"github.com/ipld/go-ipld-prime/node/basicnode"
	"github.com/multiformats/go-multihash"
	"github.com/tmc/go-iroh/blobs"
)

// Tables stores the CID-to-blob and CID-to-link metadata used by dagsync.
type Tables struct {
	mu       sync.RWMutex
	hashes   map[string]blobs.Hash
	links    map[string][]cid.Cid
	revLinks map[blobs.Hash][]cid.Cid
}

// NewTables returns empty in-memory tables.
func NewTables() *Tables {
	return &Tables{
		hashes:   make(map[string]blobs.Hash),
		links:    make(map[string][]cid.Cid),
		revLinks: make(map[blobs.Hash][]cid.Cid),
	}
}

// Put records a CID, its BLAKE3 blob hash, and its outgoing links.
func (t *Tables) Put(c cid.Cid, hash blobs.Hash, links []cid.Cid) {
	if t == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.init()
	t.hashes[c.KeyString()] = hash
	t.links[c.KeyString()] = cloneCIDs(links)
	t.revLinks[hash] = appendUniqueCID(t.revLinks[hash], c)
}

// ImportBytes stores data in m and records metadata in t.
func (t *Tables) ImportBytes(ctx context.Context, m *blobs.BytesMap, c cid.Cid, data []byte) (blobs.Hash, error) {
	if m == nil {
		return blobs.Hash{}, fmt.Errorf("dagsync: nil blob map")
	}
	hash, err := m.Add(data)
	if err != nil {
		return blobs.Hash{}, err
	}
	links, err := ExtractLinks(c, data)
	if err != nil {
		return blobs.Hash{}, err
	}
	t.Put(c, hash, links)
	if ctx != nil && ctx.Err() != nil {
		return blobs.Hash{}, ctx.Err()
	}
	return hash, nil
}

// BlobHash returns the BLAKE3 blob hash for c.
func (t *Tables) BlobHash(c cid.Cid) (blobs.Hash, bool) {
	if t == nil {
		return blobs.Hash{}, false
	}
	t.mu.RLock()
	defer t.mu.RUnlock()
	h, ok := t.hashes[c.KeyString()]
	return h, ok
}

// Links returns the recorded links for c.
func (t *Tables) Links(c cid.Cid) ([]cid.Cid, bool) {
	if t == nil {
		return nil, false
	}
	t.mu.RLock()
	defer t.mu.RUnlock()
	links, ok := t.links[c.KeyString()]
	return cloneCIDs(links), ok
}

// CIDsForHash returns CIDs recorded for hash.
func (t *Tables) CIDsForHash(hash blobs.Hash) []cid.Cid {
	if t == nil {
		return nil
	}
	t.mu.RLock()
	defer t.mu.RUnlock()
	return cloneCIDs(t.revLinks[hash])
}

func (t *Tables) init() {
	if t.hashes == nil {
		t.hashes = make(map[string]blobs.Hash)
	}
	if t.links == nil {
		t.links = make(map[string][]cid.Cid)
	}
	if t.revLinks == nil {
		t.revLinks = make(map[blobs.Hash][]cid.Cid)
	}
}

func appendUniqueCID(cids []cid.Cid, c cid.Cid) []cid.Cid {
	for _, old := range cids {
		if equalCID(old, c) {
			return cids
		}
	}
	return append(cids, c)
}

func cloneCIDs(cids []cid.Cid) []cid.Cid {
	if len(cids) == 0 {
		return nil
	}
	out := make([]cid.Cid, len(cids))
	copy(out, cids)
	return out
}

// ExtractLinks returns IPLD links from data for c's codec.
func ExtractLinks(c cid.Cid, data []byte) ([]cid.Cid, error) {
	if c.Type() == cid.Raw {
		return nil, nil
	}
	if c.Type() != cid.DagCBOR {
		return nil, nil
	}
	nb := basicnode.Prototype__Any{}.NewBuilder()
	if err := dagcbor.Decode(nb, bytes.NewReader(data)); err != nil {
		return nil, fmt.Errorf("dagsync: decode dag-cbor links: %w", err)
	}
	return nodeLinks(nb.Build()), nil
}

func nodeLinks(n datamodel.Node) []cid.Cid {
	var out []cid.Cid
	var walk func(datamodel.Node)
	walk = func(n datamodel.Node) {
		switch n.Kind() {
		case datamodel.Kind_Link:
			lnk, err := n.AsLink()
			if err != nil {
				return
			}
			if cl, ok := lnk.(cidlink.Link); ok {
				out = appendUniqueCID(out, cl.Cid)
			}
		case datamodel.Kind_Map:
			it := n.MapIterator()
			for !it.Done() {
				_, v, err := it.Next()
				if err == nil {
					walk(v)
				}
			}
		case datamodel.Kind_List:
			it := n.ListIterator()
			for !it.Done() {
				_, v, err := it.Next()
				if err == nil {
					walk(v)
				}
			}
		}
	}
	walk(n)
	return out
}

func cidMatchesData(c cid.Cid, data []byte) error {
	decoded, err := multihash.Decode(c.Hash())
	if err != nil {
		return err
	}
	got, err := multihash.Sum(data, decoded.Code, decoded.Length)
	if err != nil {
		return err
	}
	if !bytes.Equal(got, c.Hash()) {
		return fmt.Errorf("dagsync: cid multihash mismatch")
	}
	return nil
}
