package contentdiscovery

import (
	"fmt"

	"github.com/tmc/go-iroh/blobs"
	"github.com/tmc/go-iroh/key"
	"github.com/tmc/go-iroh/postcard"
)

// ALPN is the content tracker application protocol name.
const ALPN = "n0/tracker/1"

// RequestSizeLimit is the largest accepted postcard request, in bytes.
const RequestSizeLimit = 16 * 1024

// AbsoluteTime is microseconds since the Unix epoch.
type AbsoluteTime uint64

// AnnounceKind identifies whether an announce is partial or complete.
type AnnounceKind uint32

const (
	AnnouncePartial AnnounceKind = iota
	AnnounceComplete
)

func (k AnnounceKind) String() string {
	switch k {
	case AnnouncePartial:
		return "partial"
	case AnnounceComplete:
		return "complete"
	default:
		return fmt.Sprintf("AnnounceKind(%d)", k)
	}
}

// Announce is the signed content availability statement.
//
// The field order is the wire order used by Rust: host, content, kind,
// timestamp.
type Announce struct {
	Host      key.EndpointID
	Content   blobs.HashAndFormat
	Kind      AnnounceKind
	Timestamp AbsoluteTime
}

// EncodePostcard encodes a as Rust Announce.
func (a Announce) EncodePostcard(e *postcard.Encoder) error {
	host := a.Host.Bytes()
	e.RawBytes(host[:])
	if err := e.Encode(a.Content); err != nil {
		return err
	}
	e.Uint(uint64(a.Kind))
	e.Uint(uint64(a.Timestamp))
	return nil
}

// DecodePostcard decodes a as Rust Announce.
func (a *Announce) DecodePostcard(d *postcard.Decoder) error {
	host, err := d.RawBytes(key.PublicKeySize)
	if err != nil {
		return err
	}
	pub, err := key.PublicKeyFromSlice(host)
	if err != nil {
		return err
	}
	a.Host = pub.EndpointID()
	if err := d.Decode(&a.Content); err != nil {
		return err
	}
	kind, err := d.Uint()
	if err != nil {
		return err
	}
	a.Kind = AnnounceKind(kind)
	timestamp, err := d.Uint()
	if err != nil {
		return err
	}
	a.Timestamp = AbsoluteTime(timestamp)
	return nil
}

// SignedAnnounce is an announce plus its ed25519 signature.
type SignedAnnounce struct {
	Announce  Announce
	Signature [key.SignatureSize]byte
}

// QueryFlags selects tracker query behavior.
type QueryFlags struct {
	Complete bool
	Verified bool
}

// Query asks a tracker for hosts announcing Content.
type Query struct {
	Content blobs.HashAndFormat
	Flags   QueryFlags
}

// QueryResponse is a tracker query result.
type QueryResponse struct {
	Hosts []SignedAnnounce
}

// RequestKind identifies a request variant.
type RequestKind uint64

const (
	RequestAnnounce RequestKind = iota
	RequestQuery
)

// Request is a content tracker request.
type Request struct {
	Kind     RequestKind
	Announce SignedAnnounce
	Query    Query
}

// EncodePostcard encodes r as the Rust Request enum.
func (r Request) EncodePostcard(e *postcard.Encoder) error {
	e.Uint(uint64(r.Kind))
	switch r.Kind {
	case RequestAnnounce:
		return e.Encode(r.Announce)
	case RequestQuery:
		return e.Encode(r.Query)
	default:
		return fmt.Errorf("contentdiscovery: unknown request %d", r.Kind)
	}
}

// DecodePostcard decodes r as the Rust Request enum.
func (r *Request) DecodePostcard(d *postcard.Decoder) error {
	kind, err := d.Uint()
	if err != nil {
		return err
	}
	r.Kind = RequestKind(kind)
	switch r.Kind {
	case RequestAnnounce:
		return d.Decode(&r.Announce)
	case RequestQuery:
		return d.Decode(&r.Query)
	default:
		return fmt.Errorf("contentdiscovery: unknown request %d", r.Kind)
	}
}

// ResponseKind identifies a response variant.
type ResponseKind uint64

const (
	ResponseQueryResponse ResponseKind = iota
)

// Response is a content tracker response.
type Response struct {
	Kind          ResponseKind
	QueryResponse QueryResponse
}

// EncodePostcard encodes r as the Rust Response enum.
func (r Response) EncodePostcard(e *postcard.Encoder) error {
	e.Uint(uint64(r.Kind))
	switch r.Kind {
	case ResponseQueryResponse:
		return e.Encode(r.QueryResponse)
	default:
		return fmt.Errorf("contentdiscovery: unknown response %d", r.Kind)
	}
}

// DecodePostcard decodes r as the Rust Response enum.
func (r *Response) DecodePostcard(d *postcard.Decoder) error {
	kind, err := d.Uint()
	if err != nil {
		return err
	}
	r.Kind = ResponseKind(kind)
	switch r.Kind {
	case ResponseQueryResponse:
		return d.Decode(&r.QueryResponse)
	default:
		return fmt.Errorf("contentdiscovery: unknown response %d", r.Kind)
	}
}
