package pkarrnaming

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/tmc/go-iroh/blobs"
	"github.com/tmc/go-iroh/key"
	"github.com/tmc/go-iroh/pkarr"
)

const (
	// DefaultRelayURL is the number0 production pkarr relay.
	DefaultRelayURL = "https://dns.iroh.link/pkarr"
	// DefaultTTL is the default record TTL in seconds.
	DefaultTTL uint32 = 30

	contentName = "_content"
)

// RelayClient publishes and resolves names through a pkarr HTTP relay.
type RelayClient struct {
	httpClient *http.Client
	relayURL   *url.URL
	ttl        uint32
}

// RelayOption configures a RelayClient.
type RelayOption func(*RelayClient)

// WithHTTPClient sets the HTTP client used for relay requests.
func WithHTTPClient(c *http.Client) RelayOption {
	return func(r *RelayClient) {
		if c != nil {
			r.httpClient = c
		}
	}
}

// WithTTL sets the DNS TXT record TTL in seconds.
func WithTTL(ttl uint32) RelayOption {
	return func(r *RelayClient) {
		if ttl != 0 {
			r.ttl = ttl
		}
	}
}

// NewRelayClient returns a RelayClient using relayURL.
func NewRelayClient(relayURL string, opts ...RelayOption) (*RelayClient, error) {
	if relayURL == "" {
		relayURL = DefaultRelayURL
	}
	u, err := url.Parse(relayURL)
	if err != nil {
		return nil, fmt.Errorf("pkarrnaming: parse relay url: %w", err)
	}
	r := &RelayClient{
		httpClient: &http.Client{Timeout: 30 * time.Second},
		relayURL:   u,
		ttl:        DefaultTTL,
	}
	for _, opt := range opts {
		opt(r)
	}
	return r, nil
}

// Publish publishes record r under sk.
func (r *RelayClient) Publish(ctx context.Context, sk key.SecretKey, record blobs.HashAndFormat) error {
	packet, err := pkarr.FromTxtStrings(sk, contentName, []string{RecordString(record)}, r.ttl)
	if err != nil {
		return fmt.Errorf("pkarrnaming: encode packet: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, r.keyURL(sk.Public().EndpointID().Z32()), bytes.NewReader(packet.RelayPayload()))
	if err != nil {
		return fmt.Errorf("pkarrnaming: build put request: %w", err)
	}
	resp, err := r.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("pkarrnaming: http put: %w", err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("pkarrnaming: relay returned status %d", resp.StatusCode)
	}
	return nil
}

// Resolve resolves the content record published by pk.
func (r *RelayClient) Resolve(ctx context.Context, pk key.PublicKey) (blobs.HashAndFormat, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, r.keyURL(pk.EndpointID().Z32()), nil)
	if err != nil {
		return blobs.HashAndFormat{}, fmt.Errorf("pkarrnaming: build get request: %w", err)
	}
	resp, err := r.httpClient.Do(req)
	if err != nil {
		return blobs.HashAndFormat{}, fmt.Errorf("pkarrnaming: http get: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		_, _ = io.Copy(io.Discard, resp.Body)
		return blobs.HashAndFormat{}, fmt.Errorf("pkarrnaming: relay returned status %d", resp.StatusCode)
	}
	payload, err := io.ReadAll(resp.Body)
	if err != nil {
		return blobs.HashAndFormat{}, fmt.Errorf("pkarrnaming: read payload: %w", err)
	}
	packet, err := pkarr.FromRelayPayload(pk, payload)
	if err != nil {
		return blobs.HashAndFormat{}, fmt.Errorf("pkarrnaming: decode packet: %w", err)
	}
	records := packet.TxtRecords(contentName)
	if len(records) == 0 {
		return blobs.HashAndFormat{}, fmt.Errorf("pkarrnaming: missing %s TXT record", contentName)
	}
	record, err := ParseRecord(records[0])
	if err != nil {
		return blobs.HashAndFormat{}, err
	}
	return record, nil
}

func (r *RelayClient) keyURL(z32 string) string {
	u := *r.relayURL
	u.Path = strings.TrimRight(u.Path, "/") + "/" + z32
	return u.String()
}
