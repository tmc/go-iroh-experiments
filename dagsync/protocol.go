package dagsync

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/ipfs/go-cid"
	"github.com/tmc/go-iroh/blobs"
	"github.com/tmc/go-iroh/postcard"
)

// ALPN is the iroh-dag-sync protocol name.
const ALPN = "DAG_SYNC/1"

const (
	requestSync uint64 = iota
)

const (
	traversalSequence uint64 = iota
	traversalFull
)

const (
	headerHash uint64 = iota
	headerData
)

const (
	orderDepthFirstPreOrderLeftToRight uint64 = iota
)

const (
	filterAll uint64 = iota
	filterNoRaw
	filterJustRaw
	filterExclude
)

const (
	inlineAll uint64 = iota
	inlineNoRaw
	inlineExclude
	inlineNone
)

// Request is a dagsync request.
type Request struct {
	Sync *SyncRequest
}

// SyncRequest asks for a traversal, optionally inlining block data.
type SyncRequest struct {
	Traversal TraversalOpts
	Inline    InlineOpts
}

// NewSyncRequest returns a sync request.
func NewSyncRequest(tr TraversalOpts, inline InlineOpts) Request {
	return Request{Sync: &SyncRequest{Traversal: tr, Inline: inline}}
}

// MarshalPostcard implements postcard.Marshaler.
func (r Request) MarshalPostcard() ([]byte, error) {
	var e postcard.Encoder
	if err := r.EncodePostcard(&e); err != nil {
		return nil, err
	}
	return e.Bytes(), nil
}

// EncodePostcard encodes r as a Rust-compatible enum.
func (r Request) EncodePostcard(e *postcard.Encoder) error {
	switch {
	case r.Sync != nil:
		e.Uint(requestSync)
		return e.Encode(*r.Sync)
	default:
		return errors.New("dagsync: empty request")
	}
}

// DecodePostcard decodes r from a Rust-compatible enum.
func (r *Request) DecodePostcard(d *postcard.Decoder) error {
	tag, err := d.Uint()
	if err != nil {
		return err
	}
	switch tag {
	case requestSync:
		var req SyncRequest
		if err := d.Decode(&req); err != nil {
			return err
		}
		r.Sync = &req
		return nil
	default:
		return fmt.Errorf("dagsync: unknown request tag %d", tag)
	}
}

// Cid is a postcard byte-sequence wrapper around cid.Cid.
type Cid struct {
	Cid cid.Cid
}

// NewCid wraps c.
func NewCid(c cid.Cid) Cid { return Cid{Cid: c} }

// MarshalPostcard implements postcard.Marshaler.
func (c Cid) MarshalPostcard() ([]byte, error) {
	var e postcard.Encoder
	c.EncodePostcard(&e)
	return e.Bytes(), nil
}

// EncodePostcard encodes c as cid.to_bytes(), matching Rust.
func (c Cid) EncodePostcard(e *postcard.Encoder) error {
	e.BytesValue(c.Cid.Bytes())
	return nil
}

// DecodePostcard decodes c from cid bytes.
func (c *Cid) DecodePostcard(d *postcard.Decoder) error {
	b, err := d.BytesValue()
	if err != nil {
		return err
	}
	parsed, err := cid.Cast(b)
	if err != nil {
		return fmt.Errorf("dagsync: decode cid: %w", err)
	}
	c.Cid = parsed
	return nil
}

// TraversalOpts selects the traversal strategy.
type TraversalOpts struct {
	Sequence *SequenceTraversalOpts
	Full     *FullTraversalOpts
}

// SequenceTraversal returns a traversal over explicit CIDs.
func SequenceTraversal(cids ...cid.Cid) TraversalOpts {
	out := make([]Cid, len(cids))
	for i, c := range cids {
		out[i] = NewCid(c)
	}
	return TraversalOpts{Sequence: &SequenceTraversalOpts{Cids: out}}
}

// FullTraversal returns a depth-first traversal rooted at root.
func FullTraversal(root cid.Cid) TraversalOpts {
	return TraversalOpts{Full: &FullTraversalOpts{
		Root:   NewCid(root),
		Order:  &TraversalOrder{DepthFirstPreOrderLeftToRight: true},
		Filter: &TraversalFilter{All: true},
	}}
}

// EncodePostcard encodes t as a Rust-compatible enum.
func (t TraversalOpts) EncodePostcard(e *postcard.Encoder) error {
	switch {
	case t.Sequence != nil:
		e.Uint(traversalSequence)
		return e.Encode(*t.Sequence)
	case t.Full != nil:
		e.Uint(traversalFull)
		return e.Encode(*t.Full)
	default:
		return errors.New("dagsync: empty traversal")
	}
}

// DecodePostcard decodes t from a Rust-compatible enum.
func (t *TraversalOpts) DecodePostcard(d *postcard.Decoder) error {
	tag, err := d.Uint()
	if err != nil {
		return err
	}
	switch tag {
	case traversalSequence:
		var seq SequenceTraversalOpts
		if err := d.Decode(&seq); err != nil {
			return err
		}
		t.Sequence, t.Full = &seq, nil
	case traversalFull:
		var full FullTraversalOpts
		if err := d.Decode(&full); err != nil {
			return err
		}
		t.Full, t.Sequence = &full, nil
	default:
		return fmt.Errorf("dagsync: unknown traversal tag %d", tag)
	}
	return nil
}

// SequenceTraversalOpts holds explicit CIDs.
type SequenceTraversalOpts struct {
	Cids []Cid
}

// FullTraversalOpts holds full DAG traversal options.
type FullTraversalOpts struct {
	Root    Cid
	Visited []Cid
	Order   *TraversalOrder
	Filter  *TraversalFilter
}

// TraversalOrder selects the traversal order.
type TraversalOrder struct {
	DepthFirstPreOrderLeftToRight bool
}

// EncodePostcard encodes o as a Rust-compatible enum.
func (o TraversalOrder) EncodePostcard(e *postcard.Encoder) error {
	if !o.DepthFirstPreOrderLeftToRight {
		return errors.New("dagsync: empty traversal order")
	}
	e.Uint(orderDepthFirstPreOrderLeftToRight)
	return nil
}

// DecodePostcard decodes o from a Rust-compatible enum.
func (o *TraversalOrder) DecodePostcard(d *postcard.Decoder) error {
	tag, err := d.Uint()
	if err != nil {
		return err
	}
	if tag != orderDepthFirstPreOrderLeftToRight {
		return fmt.Errorf("dagsync: unknown traversal order tag %d", tag)
	}
	o.DepthFirstPreOrderLeftToRight = true
	return nil
}

// TraversalFilter filters CIDs during traversal.
type TraversalFilter struct {
	All     bool
	NoRaw   bool
	JustRaw bool
	Exclude []uint64
}

// EncodePostcard encodes f as a Rust-compatible enum.
func (f TraversalFilter) EncodePostcard(e *postcard.Encoder) error {
	switch {
	case f.All:
		e.Uint(filterAll)
	case f.NoRaw:
		e.Uint(filterNoRaw)
	case f.JustRaw:
		e.Uint(filterJustRaw)
	case f.Exclude != nil:
		e.Uint(filterExclude)
		return e.Encode(f.Exclude)
	default:
		return errors.New("dagsync: empty traversal filter")
	}
	return nil
}

// DecodePostcard decodes f from a Rust-compatible enum.
func (f *TraversalFilter) DecodePostcard(d *postcard.Decoder) error {
	tag, err := d.Uint()
	if err != nil {
		return err
	}
	*f = TraversalFilter{}
	switch tag {
	case filterAll:
		f.All = true
	case filterNoRaw:
		f.NoRaw = true
	case filterJustRaw:
		f.JustRaw = true
	case filterExclude:
		if err := d.Decode(&f.Exclude); err != nil {
			return err
		}
	default:
		return fmt.Errorf("dagsync: unknown traversal filter tag %d", tag)
	}
	return nil
}

// InlineOpts selects which response items carry data.
type InlineOpts struct {
	All     bool
	NoRaw   bool
	Exclude []uint64
	None    bool
}

// InlineAll returns the Rust default inline mode.
func InlineAll() InlineOpts { return InlineOpts{All: true} }

// EncodePostcard encodes i as a Rust-compatible enum.
func (i InlineOpts) EncodePostcard(e *postcard.Encoder) error {
	switch {
	case i.All:
		e.Uint(inlineAll)
	case i.NoRaw:
		e.Uint(inlineNoRaw)
	case i.Exclude != nil:
		e.Uint(inlineExclude)
		return e.Encode(i.Exclude)
	case i.None:
		e.Uint(inlineNone)
	default:
		return errors.New("dagsync: empty inline opts")
	}
	return nil
}

// DecodePostcard decodes i from a Rust-compatible enum.
func (i *InlineOpts) DecodePostcard(d *postcard.Decoder) error {
	tag, err := d.Uint()
	if err != nil {
		return err
	}
	*i = InlineOpts{}
	switch tag {
	case inlineAll:
		i.All = true
	case inlineNoRaw:
		i.NoRaw = true
	case inlineExclude:
		if err := d.Decode(&i.Exclude); err != nil {
			return err
		}
	case inlineNone:
		i.None = true
	default:
		return fmt.Errorf("dagsync: unknown inline tag %d", tag)
	}
	return nil
}

// SyncResponseHeader is one response item header.
type SyncResponseHeader struct {
	Hash *blobs.Hash
	Data *blobs.Hash
}

// HashHeader returns a hash-only response header.
func HashHeader(h blobs.Hash) SyncResponseHeader { return SyncResponseHeader{Hash: &h} }

// DataHeader returns a data-carrying response header.
func DataHeader(h blobs.Hash) SyncResponseHeader { return SyncResponseHeader{Data: &h} }

// MarshalPostcard implements postcard.Marshaler.
func (h SyncResponseHeader) MarshalPostcard() ([]byte, error) {
	var e postcard.Encoder
	if err := h.EncodePostcard(&e); err != nil {
		return nil, err
	}
	return e.Bytes(), nil
}

// EncodePostcard encodes h as a 33-byte Rust-compatible enum.
func (h SyncResponseHeader) EncodePostcard(e *postcard.Encoder) error {
	switch {
	case h.Hash != nil:
		e.Uint(headerHash)
		e.RawBytes(h.Hash[:])
	case h.Data != nil:
		e.Uint(headerData)
		e.RawBytes(h.Data[:])
	default:
		return errors.New("dagsync: empty response header")
	}
	return nil
}

// DecodePostcard decodes h from a 33-byte Rust-compatible enum.
func (h *SyncResponseHeader) DecodePostcard(d *postcard.Decoder) error {
	tag, err := d.Uint()
	if err != nil {
		return err
	}
	b, err := d.RawBytes(blobs.HashSize)
	if err != nil {
		return err
	}
	var hash blobs.Hash
	copy(hash[:], b)
	switch tag {
	case headerHash:
		h.Hash, h.Data = &hash, nil
	case headerData:
		h.Data, h.Hash = &hash, nil
	default:
		return fmt.Errorf("dagsync: unknown response header tag %d", tag)
	}
	return nil
}

// Bytes returns h encoded as the fixed 33-byte response header.
func (h SyncResponseHeader) Bytes() ([33]byte, error) {
	var out [33]byte
	b, err := h.MarshalPostcard()
	if err != nil {
		return out, err
	}
	if len(b) != len(out) {
		return out, fmt.Errorf("dagsync: response header length %d", len(b))
	}
	copy(out[:], b)
	return out, nil
}

func inlinePredicate(opts InlineOpts) func(cid.Cid) bool {
	switch {
	case opts.All:
		return func(cid.Cid) bool { return true }
	case opts.NoRaw:
		return func(c cid.Cid) bool { return c.Type() != cid.Raw }
	case opts.Exclude != nil:
		exclude := make(map[uint64]bool)
		for _, codec := range opts.Exclude {
			exclude[codec] = true
		}
		return func(c cid.Cid) bool { return !exclude[c.Type()] }
	default:
		return func(cid.Cid) bool { return false }
	}
}

func decodePostcard(data []byte, v any) error {
	if err := postcard.Unmarshal(data, v); err != nil {
		return err
	}
	return nil
}

func encodePostcard(v any) ([]byte, error) {
	return postcard.Marshal(v)
}

func checkNoTrailing(d *postcard.Decoder) error {
	if !d.Done() {
		return errors.New("dagsync: trailing postcard bytes")
	}
	return nil
}

func decodeHeader(b []byte) (SyncResponseHeader, error) {
	var h SyncResponseHeader
	d := postcard.NewDecoder(b)
	if err := d.Decode(&h); err != nil {
		return h, err
	}
	if err := checkNoTrailing(d); err != nil {
		return h, err
	}
	return h, nil
}

func equalCID(a, b cid.Cid) bool {
	return bytes.Equal(a.Bytes(), b.Bytes())
}
