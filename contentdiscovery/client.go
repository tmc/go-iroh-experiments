package contentdiscovery

import (
	"context"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/tmc/go-iroh/blobs"
	"github.com/tmc/go-iroh/iroh"
	"github.com/tmc/go-iroh/key"
	"github.com/tmc/go-iroh/netaddr"
	"github.com/tmc/go-iroh/postcard"
)

// Client sends content discovery requests to trackers.
type Client struct {
	ep *iroh.Endpoint
}

// NewClient returns a content discovery client using ep.
func NewClient(ep *iroh.Endpoint) *Client { return &Client{ep: ep} }

// Announce announces content to tracker.
func (c *Client) Announce(ctx context.Context, tracker netaddr.EndpointAddr, sk key.SecretKey, content blobs.HashAndFormat, kind AnnounceKind) error {
	announce := Announce{
		Host:      sk.Public().EndpointID(),
		Content:   content,
		Kind:      kind,
		Timestamp: Now(),
	}
	sa, err := SignAnnounce(sk, announce)
	if err != nil {
		return err
	}
	_, err = c.send(ctx, tracker, Request{Kind: RequestAnnounce, Announce: sa})
	return err
}

// AnnounceAll announces content to each tracker.
func (c *Client) AnnounceAll(ctx context.Context, trackers []netaddr.EndpointAddr, sk key.SecretKey, content blobs.HashAndFormat, kind AnnounceKind) error {
	return eachTracker(ctx, trackers, func(ctx context.Context, tracker netaddr.EndpointAddr) error {
		return c.Announce(ctx, tracker, sk, content, kind)
	})
}

// Query asks tracker for hosts announcing content.
func (c *Client) Query(ctx context.Context, tracker netaddr.EndpointAddr, content blobs.HashAndFormat, flags QueryFlags) ([]SignedAnnounce, error) {
	resp, err := c.send(ctx, tracker, Request{
		Kind:  RequestQuery,
		Query: Query{Content: content, Flags: flags},
	})
	if err != nil {
		return nil, err
	}
	return resp.QueryResponse.Hosts, nil
}

// QueryAll asks every tracker for hosts announcing content.
func (c *Client) QueryAll(ctx context.Context, trackers []netaddr.EndpointAddr, content blobs.HashAndFormat, flags QueryFlags) ([]SignedAnnounce, error) {
	var (
		mu  sync.Mutex
		out []SignedAnnounce
	)
	err := eachTracker(ctx, trackers, func(ctx context.Context, tracker netaddr.EndpointAddr) error {
		hosts, err := c.Query(ctx, tracker, content, flags)
		if err != nil {
			return err
		}
		mu.Lock()
		out = append(out, hosts...)
		mu.Unlock()
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// Now returns the current wall-clock time in microseconds since the Unix epoch.
func Now() AbsoluteTime { return AbsoluteTime(time.Now().UnixMicro()) }

func (c *Client) send(ctx context.Context, tracker netaddr.EndpointAddr, req Request) (Response, error) {
	conn, err := c.ep.Connect(ctx, tracker, ALPN)
	if err != nil {
		return Response{}, fmt.Errorf("contentdiscovery: connect tracker: %w", err)
	}
	defer conn.CloseWithError(0, "")

	s, err := conn.OpenStreamSync(ctx)
	if err != nil {
		return Response{}, fmt.Errorf("contentdiscovery: open stream: %w", err)
	}
	reqBytes, err := postcard.Marshal(req)
	if err != nil {
		return Response{}, fmt.Errorf("contentdiscovery: encode request: %w", err)
	}
	if len(reqBytes) > RequestSizeLimit {
		return Response{}, errRequestTooLarge
	}
	if _, err := s.Write(reqBytes); err != nil {
		return Response{}, fmt.Errorf("contentdiscovery: write request: %w", err)
	}
	if err := s.Close(); err != nil {
		return Response{}, fmt.Errorf("contentdiscovery: close request: %w", err)
	}
	respBytes, err := readLimited(s, RequestSizeLimit)
	if err != nil && err != io.EOF {
		return Response{}, err
	}
	var resp Response
	if err := postcard.Unmarshal(respBytes, &resp); err != nil {
		return Response{}, fmt.Errorf("contentdiscovery: decode response: %w", err)
	}
	return resp, nil
}

func eachTracker(ctx context.Context, trackers []netaddr.EndpointAddr, f func(context.Context, netaddr.EndpointAddr) error) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	errc := make(chan error, len(trackers))
	for _, tracker := range trackers {
		tracker := tracker
		go func() {
			errc <- f(ctx, tracker)
		}()
	}
	for range trackers {
		if err := <-errc; err != nil {
			cancel()
			return err
		}
	}
	return nil
}
