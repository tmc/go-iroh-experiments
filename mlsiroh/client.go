package mlsiroh

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"time"

	"github.com/tmc/go-iroh/iroh"
	"github.com/tmc/go-iroh/key"
	"github.com/tmc/go-iroh/netaddr"
	"github.com/tmc/mls"
)

// FetchKeyPackage fetches one key package for the given cipher suite
// from the directory at addr and consumes it: the directory will not
// serve it again.
//
// The returned key package is verified against the iroh:ed25519
// binding and must name the endpoint in addr, so a directory cannot
// hand back a key package for somebody else.
func FetchKeyPackage(ctx context.Context, ep *iroh.Endpoint, addr netaddr.EndpointAddr, suite mls.CipherSuite) (*mls.KeyPackage, error) {
	body, err := mls.Marshal(&fetchKeyPackageBody{CipherSuite: suite})
	if err != nil {
		return nil, err
	}
	b, err := roundTrip(ctx, ep, addr, opFetchKeyPackage, body)
	if err != nil {
		return nil, err
	}
	return servedKeyPackage(b, addr.ID, time.Now())
}

// servedKeyPackage parses and verifies a key package the directory of
// endpoint from served.
func servedKeyPackage(b []byte, from key.EndpointID, now time.Time) (*mls.KeyPackage, error) {
	var msg mls.Message
	if err := mls.Unmarshal(b, &msg); err != nil {
		return nil, fmt.Errorf("mlsiroh: decoding key package: %w", err)
	}
	if msg.WireFormat != mls.WireFormatKeyPackage || msg.KeyPackage == nil {
		return nil, fmt.Errorf("mlsiroh: wanted a key package, got %v", msg.WireFormat)
	}
	id, err := Verify(msg.KeyPackage, now)
	if err != nil {
		return nil, err
	}
	if !id.Equal(from) {
		return nil, fmt.Errorf("%w: key package names %v, asked %v", ErrWrongEndpoint, id, from)
	}
	return msg.KeyPackage, nil
}

// DeliverWelcome delivers w to the directory at addr, which must have
// served a key package w names, within that key package's lifetime and
// a day after it.
//
// The directory refuses with [ErrNotFound] a Welcome naming no key
// package it served; with [ErrExhausted] one past its delivery rate or
// past the few Welcomes it accepts for one key package; and with
// [ErrUnavailable] one that finds its queue full, whether in all or of
// this sender's share. Only the last is worth retrying.
//
// Success acknowledges a volatile queue entry, not durable delivery or a
// completed join. The recipient must separately acknowledge its joined epoch.
//
// The caller must not call DeliverWelcome until the commit that
// produced w is known to have been accepted by the group. RFC 9420,
// Section 14, forbids delivering a Welcome before then: a joiner that
// acts on the Welcome of a commit that lost lands in an epoch no
// member is in. For a group whose commits are sequenced, "accepted"
// means the commit appeared as the first valid one for its epoch.
func DeliverWelcome(ctx context.Context, ep *iroh.Endpoint, addr netaddr.EndpointAddr, w *mls.Welcome) error {
	body, err := mls.Marshal(&mls.Message{
		Version:    mls.Version10,
		WireFormat: mls.WireFormatWelcome,
		Welcome:    w,
	})
	if err != nil {
		return err
	}
	_, err = roundTrip(ctx, ep, addr, opDeliverWelcome, body)
	return err
}

// FetchGroupInfo fetches the GroupInfo the directory at addr publishes
// for the named group. A caller the directory's policy does not admit
// gets [StatusNotFound], the same as for a group that does not exist.
//
// The result is what [github.com/tmc/mls.Client.JoinExternal] takes: it
// carries the ratchet tree and the external_pub the caller needs to
// commit itself into the group. It is good for one join, since the join
// ends the epoch it describes; a stale one produces a commit that the
// group rejects with mls.ErrNotForGroup, which is the signal to refetch.
func FetchGroupInfo(ctx context.Context, ep *iroh.Endpoint, addr netaddr.EndpointAddr, groupID []byte) (*mls.GroupInfo, error) {
	body, err := mls.Marshal(&fetchGroupInfoBody{GroupID: groupID})
	if err != nil {
		return nil, err
	}
	b, err := roundTrip(ctx, ep, addr, opFetchGroupInfo, body)
	if err != nil {
		return nil, err
	}
	return servedGroupInfo(b, groupID, addr.ID)
}

// servedGroupInfo parses and checks a GroupInfo for groupID that the
// directory of endpoint from served.
func servedGroupInfo(b, groupID []byte, from key.EndpointID) (*mls.GroupInfo, error) {
	var msg mls.Message
	if err := mls.Unmarshal(b, &msg); err != nil {
		return nil, fmt.Errorf("mlsiroh: decoding group info: %w", err)
	}
	if msg.WireFormat != mls.WireFormatGroupInfo || msg.GroupInfo == nil {
		return nil, fmt.Errorf("mlsiroh: wanted a group info, got %v", msg.WireFormat)
	}
	info := msg.GroupInfo
	// Everything mls checks about a GroupInfo is internally consistent:
	// the tree against the group context and the signature against a
	// leaf of that same tree. A whole group can be fabricated and still
	// pass. So the two facts the transport knows and mls does not -
	// which group we asked for, and which endpoint answered - are
	// checked here, as they are for a key package, along with the
	// signature that ties the GroupInfo to its signer's leaf.
	if !bytes.Equal(info.GroupContext.GroupID, groupID) {
		return nil, fmt.Errorf("%w: group info is for %x, asked %x", ErrWrongGroup, info.GroupContext.GroupID, groupID)
	}
	signer, err := verifyGroupInfo(info)
	if err != nil {
		return nil, err
	}
	if !signer.Equal(from) {
		return nil, fmt.Errorf("%w: group info signed by %v, served by %v", ErrWrongEndpoint, signer, from)
	}
	return info, nil
}

// roundTrip sends one request to addr and returns the response body,
// or an [Error] if the directory reported a status other than ok.
func roundTrip(ctx context.Context, ep *iroh.Endpoint, addr netaddr.EndpointAddr, o op, body []byte) ([]byte, error) {
	conn, err := ep.Connect(ctx, addr, ALPN)
	if err != nil {
		return nil, fmt.Errorf("mlsiroh: connecting to %v: %w", addr.ID, err)
	}
	defer conn.Close()
	// Connect returns only after the handshake, so the peer key is
	// verified; check it anyway, because the whole design rests on
	// the endpoint we talked to being the endpoint we asked for.
	if got := conn.RemoteID(); !got.Equal(addr.ID) {
		return nil, fmt.Errorf("%w: connected to %v, asked %v", ErrWrongEndpoint, got, addr.ID)
	}
	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		return nil, err
	}
	defer stream.Close()
	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(readTimeout)
	}
	if err := stream.SetDeadline(deadline); err != nil {
		return nil, err
	}
	// A canceled ctx with no deadline must still stop the stream.
	stop := context.AfterFunc(ctx, func() { stream.SetDeadline(time.Now()) })
	defer stop()

	req, err := mls.Marshal(&request{Version: version, Op: o, Body: body})
	if err != nil {
		return nil, err
	}
	if max := o.maxRequestSize(); len(req) > max {
		return nil, fmt.Errorf("mlsiroh: %v request is %d bytes, over the %d limit", o, len(req), max)
	}
	if _, err := stream.Write(req); err != nil {
		return nil, err
	}
	if err := stream.CloseWrite(); err != nil {
		return nil, err
	}

	max := o.maxResponseSize() + MaxRequestSize
	b, err := io.ReadAll(io.LimitReader(stream, int64(max)+1))
	if err != nil {
		if ctx.Err() != nil {
			return nil, fmt.Errorf("mlsiroh: %v: %w", o, ctx.Err())
		}
		return nil, err
	}
	return decodeResponse(o, b)
}

// decodeResponse parses the response to an o request and returns its
// body, or an [Error] if the directory reported a status other than ok.
func decodeResponse(o op, b []byte) ([]byte, error) {
	if max := o.maxResponseSize() + MaxRequestSize; len(b) > max {
		return nil, fmt.Errorf("mlsiroh: %v response over the %d byte limit", o, max)
	}
	var resp response
	if err := mls.Unmarshal(b, &resp); err != nil {
		return nil, fmt.Errorf("mlsiroh: decoding response: %w", err)
	}
	if resp.Version != version {
		return nil, fmt.Errorf("mlsiroh: response version %d", resp.Version)
	}
	if resp.Status != StatusOK {
		return nil, &Error{Op: o.String(), Status: resp.Status}
	}
	return resp.Body, nil
}
