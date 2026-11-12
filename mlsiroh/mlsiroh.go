package mlsiroh

import (
	"fmt"

	"github.com/tmc/mls"
	"github.com/tmc/mls/tlssyntax"
)

// ALPN is the application-layer protocol negotiation value for the
// mlsiroh delivery service.
const ALPN = "mlsiroh/ds/1"

// version is the protocol version carried in every request and
// response. It changes only when the framing changes incompatibly.
const version = 1

// An op identifies a delivery service operation.
type op uint8

const (
	opFetchKeyPackage op = 1
	opDeliverWelcome  op = 2
	opFetchGroupInfo  op = 3
)

func (o op) String() string {
	switch o {
	case opFetchKeyPackage:
		return "fetch_key_package"
	case opDeliverWelcome:
		return "deliver_welcome"
	case opFetchGroupInfo:
		return "fetch_group_info"
	}
	return fmt.Sprintf("op(%d)", uint8(o))
}

// A Status is the outcome a directory reports for a request.
type Status uint8

const (
	// StatusOK reports that the request succeeded.
	StatusOK Status = 0

	// StatusNotFound reports that the directory has nothing to
	// serve for the request, or that the caller is not authorized
	// to know whether it does. The two are deliberately not
	// distinguished: see [Directory.PublishGroupInfo].
	StatusNotFound Status = 1

	// StatusExhausted reports that a bounded resource is spent: the
	// directory has no unused key package for the requested cipher
	// suite, its policy does not admit the caller, the caller or all
	// callers together have used up this window's fetches or
	// deliveries, or the key package a Welcome names has had its
	// Welcomes. The cases are deliberately not distinguished, so that
	// the answer is not an oracle for the policy.
	StatusExhausted Status = 2

	// StatusMalformed reports that the request did not decode, or
	// that its body failed validation.
	StatusMalformed Status = 3

	// StatusUnsupported reports an unknown operation, protocol
	// version, or cipher suite.
	StatusUnsupported Status = 4

	// StatusUnavailable reports that the directory could not serve
	// the request for a reason on its own side: a journal it could
	// not read or write, a queue nobody is draining or that holds the
	// caller's share, a shutdown in progress, a policy that panicked.
	// Unlike every other status it invites a retry, and it is
	// deliberately distinct from StatusNotFound so that an internal
	// failure is not reported as an absence.
	StatusUnavailable Status = 5
)

// Errors that match an [*Error] of the same status under [errors.Is],
// whatever its operation.
var (
	ErrNotFound    error = &Error{Status: StatusNotFound}
	ErrExhausted   error = &Error{Status: StatusExhausted}
	ErrUnavailable error = &Error{Status: StatusUnavailable}
)

// String returns the status as the protocol names it, such as
// "not_found".
func (s Status) String() string {
	switch s {
	case StatusOK:
		return "ok"
	case StatusNotFound:
		return "not_found"
	case StatusExhausted:
		return "exhausted"
	case StatusMalformed:
		return "malformed"
	case StatusUnsupported:
		return "unsupported"
	case StatusUnavailable:
		return "unavailable"
	}
	return fmt.Sprintf("status(%d)", uint8(s))
}

// An Error is a status other than [StatusOK] returned by a directory.
type Error struct {
	Op     string
	Status Status
}

// Error returns the operation and the status, such as
// "fetch_key_package: exhausted".
func (e *Error) Error() string {
	if e.Op == "" {
		return "mlsiroh: " + e.Status.String()
	}
	return e.Op + ": " + e.Status.String()
}

// Is reports whether target is an *Error with the same status and
// either the same operation or none.
func (e *Error) Is(target error) bool {
	t, ok := target.(*Error)
	return ok && t.Status == e.Status && (t.Op == "" || t.Op == e.Op)
}

// Size limits for the three operations. They differ because the
// messages differ by orders of magnitude: a request is a few bytes,
// a key package a few hundred, and a GroupInfo carrying the ratchet
// tree of a large group runs to megabytes. One limit for all three
// would either reject legitimate group info or let a request be
// gigabytes.
const (
	// MaxRequestSize is the largest request a directory will read for
	// any operation but deliver_welcome, which may be larger by the
	// Welcome it carries, up to MaxWelcomeSize.
	MaxRequestSize = 64 << 10

	// MaxKeyPackageSize is the largest key package a directory will
	// serve or a client will accept.
	MaxKeyPackageSize = 64 << 10

	// MaxWelcomeSize is the largest Welcome a directory will accept.
	// A Welcome holds one encrypted GroupSecrets per new member.
	MaxWelcomeSize = 4 << 20

	// MaxGroupInfoSize is the largest GroupInfo a directory will
	// serve or a client will accept. A GroupInfo carries the whole
	// ratchet tree.
	MaxGroupInfoSize = 16 << 20
)

// maxRequestSize returns the largest request the given operation can
// carry. A Welcome travels inside a request, so bounding every request
// by MaxRequestSize would put a ceiling on group size far below
// MaxWelcomeSize: a Welcome carries the whole ratchet tree, so it passes
// 64 KiB at a couple of hundred members.
func (o op) maxRequestSize() int {
	if o == opDeliverWelcome {
		return MaxWelcomeSize + MaxRequestSize
	}
	return MaxRequestSize
}

// maxResponseSize returns the largest response body the given
// operation can produce.
func (o op) maxResponseSize() int {
	switch o {
	case opFetchKeyPackage:
		return MaxKeyPackageSize
	case opFetchGroupInfo:
		return MaxGroupInfoSize
	}
	return 0
}

// A request is one delivery service operation and its arguments. The
// body is opaque at this layer so that a request for an operation we
// do not implement still decodes, and so the size of the body is
// checked before it is interpreted.
type request struct {
	Version uint16
	Op      op
	Body    []byte
}

func (r *request) MarshalTLS(w *tlssyntax.Writer) {
	w.WriteUint16(r.Version)
	w.WriteUint8(uint8(r.Op))
	w.WriteOpaque(r.Body)
}

func (r *request) UnmarshalTLS(rd *tlssyntax.Reader) {
	*r = request{}
	r.Version = rd.ReadUint16()
	r.Op = op(rd.ReadUint8())
	r.Body = rd.ReadOpaque()
}

// A response is the outcome of one operation. Body is empty unless
// Status is StatusOK.
type response struct {
	Version uint16
	Status  Status
	Body    []byte
}

func (r *response) MarshalTLS(w *tlssyntax.Writer) {
	w.WriteUint16(r.Version)
	w.WriteUint8(uint8(r.Status))
	w.WriteOpaque(r.Body)
}

func (r *response) UnmarshalTLS(rd *tlssyntax.Reader) {
	*r = response{}
	r.Version = rd.ReadUint16()
	r.Status = Status(rd.ReadUint8())
	r.Body = rd.ReadOpaque()
}

// fetchKeyPackageBody is the body of a fetch_key_package request.
type fetchKeyPackageBody struct {
	CipherSuite mls.CipherSuite
}

func (b *fetchKeyPackageBody) MarshalTLS(w *tlssyntax.Writer) {
	w.WriteUint16(uint16(b.CipherSuite))
}

func (b *fetchKeyPackageBody) UnmarshalTLS(r *tlssyntax.Reader) {
	b.CipherSuite = mls.CipherSuite(r.ReadUint16())
}

// fetchGroupInfoBody is the body of a fetch_group_info request.
type fetchGroupInfoBody struct {
	GroupID []byte
}

func (b *fetchGroupInfoBody) MarshalTLS(w *tlssyntax.Writer) {
	w.WriteOpaque(b.GroupID)
}

func (b *fetchGroupInfoBody) UnmarshalTLS(r *tlssyntax.Reader) {
	b.GroupID = r.ReadOpaque()
}
