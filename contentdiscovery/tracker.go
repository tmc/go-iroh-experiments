package contentdiscovery

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"

	"github.com/tmc/go-iroh/iroh"
	"github.com/tmc/go-iroh/postcard"
)

var errRequestTooLarge = errors.New("contentdiscovery: request too large")

// TrackerHandler handles content discovery tracker requests.
type TrackerHandler struct {
	store *Store
}

// NewTrackerHandler returns a tracker handler backed by store.
func NewTrackerHandler(store *Store) *TrackerHandler {
	return &TrackerHandler{store: store}
}

// Handler returns h as an iroh protocol handler.
func (h *TrackerHandler) Handler() iroh.ProtocolHandler { return h }

// Accept handles content discovery streams on conn.
func (h *TrackerHandler) Accept(ctx context.Context, conn *iroh.Conn) error {
	defer conn.CloseWithError(0, "")
	for {
		s, err := conn.AcceptStream(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return err
		}
		if err := h.handleStream(s); err != nil {
			s.CancelRead(0)
			s.CancelWrite(0)
			return err
		}
	}
}

func (h *TrackerHandler) handleStream(s *iroh.Stream) error {
	data, err := readLimited(s, RequestSizeLimit)
	if err != nil {
		return err
	}
	resp, err := h.HandleRequest(data)
	if err != nil {
		return err
	}
	if _, err := s.Write(resp); err != nil {
		return fmt.Errorf("contentdiscovery: write response: %w", err)
	}
	if err := s.Close(); err != nil {
		return fmt.Errorf("contentdiscovery: close stream: %w", err)
	}
	return nil
}

// HandleRequest handles one encoded Request and returns an encoded Response.
func (h *TrackerHandler) HandleRequest(data []byte) ([]byte, error) {
	if len(data) > RequestSizeLimit {
		return nil, errRequestTooLarge
	}
	var req Request
	if err := postcard.Unmarshal(data, &req); err != nil {
		return nil, fmt.Errorf("contentdiscovery: decode request: %w", err)
	}
	switch req.Kind {
	case RequestAnnounce:
		if !VerifySignedAnnounce(req.Announce) {
			return nil, errors.New("contentdiscovery: invalid announce signature")
		}
		if err := h.store.PutAnnounce(req.Announce); err != nil {
			return nil, err
		}
		return postcard.Marshal(Response{Kind: ResponseQueryResponse})
	case RequestQuery:
		hosts, err := h.store.Query(req.Query)
		if err != nil {
			return nil, err
		}
		return postcard.Marshal(Response{
			Kind:          ResponseQueryResponse,
			QueryResponse: QueryResponse{Hosts: hosts},
		})
	default:
		return nil, fmt.Errorf("contentdiscovery: unknown request %d", req.Kind)
	}
}

func readLimited(r io.Reader, limit int64) ([]byte, error) {
	var b bytes.Buffer
	n, err := b.ReadFrom(io.LimitReader(r, limit+1))
	if err != nil {
		return nil, fmt.Errorf("contentdiscovery: read request: %w", err)
	}
	if n > limit {
		return nil, errRequestTooLarge
	}
	return b.Bytes(), nil
}
