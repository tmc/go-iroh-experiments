package contentdiscovery

import (
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/tmc/go-iroh/blobs"
	"github.com/tmc/go-iroh/key"
	"github.com/tmc/go-iroh/postcard"
)

const storeKeySize = blobs.HashSize + 1 + 1 + key.PublicKeySize

// Store stores content discovery announcements.
type Store struct {
	mu       sync.RWMutex
	announce map[storeKey]SignedAnnounce
	expiry   time.Duration
}

// NewStore returns an empty announcement store.
func NewStore(expiry time.Duration) *Store {
	return &Store{
		announce: make(map[storeKey]SignedAnnounce),
		expiry:   expiry,
	}
}

// PutAnnounce stores sa, replacing any previous announce for the same host,
// content, and kind.
func (s *Store) PutAnnounce(sa SignedAnnounce) error {
	k, err := makeStoreKey(sa.Announce.Content, sa.Announce.Kind, sa.Announce.Host)
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.announce[k] = sa
	s.mu.Unlock()
	return nil
}

// Query returns announces matching q.
func (s *Store) Query(q Query) ([]SignedAnnounce, error) {
	prefix := q.Content.Hash.Bytes()
	s.mu.RLock()
	defer s.mu.RUnlock()

	var out []SignedAnnounce
	for k, sa := range s.announce {
		if k.hash != prefix {
			continue
		}
		if sa.Announce.Content != q.Content {
			continue
		}
		if q.Flags.Complete && sa.Announce.Kind != AnnounceComplete {
			continue
		}
		if q.Flags.Verified && !VerifySignedAnnounce(sa) {
			continue
		}
		out = append(out, sa)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].Announce.Host.Compare(out[j].Announce.Host) < 0
	})
	return out, nil
}

// GC removes entries older than now-expiry. If expiry is zero, GC does nothing.
func (s *Store) GC(now AbsoluteTime) error {
	if s.expiry <= 0 {
		return nil
	}
	cutoff := uint64(now) - uint64(s.expiry/time.Microsecond)
	if uint64(now) < uint64(s.expiry/time.Microsecond) {
		cutoff = 0
	}

	s.mu.Lock()
	for k, sa := range s.announce {
		if sa.Announce.Timestamp < AbsoluteTime(cutoff) {
			delete(s.announce, k)
		}
	}
	s.mu.Unlock()
	return nil
}

// VerifySignedAnnounce reports whether sa's signature verifies.
func VerifySignedAnnounce(sa SignedAnnounce) bool {
	b, err := postcard.Marshal(sa.Announce)
	if err != nil {
		return false
	}
	sig := key.NewSignature(sa.Signature)
	return sa.Announce.Host.PublicKey().Verify(b, sig) == nil
}

// SignAnnounce signs a for sk.
func SignAnnounce(sk key.SecretKey, a Announce) (SignedAnnounce, error) {
	if !a.Host.Equal(sk.Public().EndpointID()) {
		return SignedAnnounce{}, errors.New("contentdiscovery: announce host does not match secret key")
	}
	b, err := postcard.Marshal(a)
	if err != nil {
		return SignedAnnounce{}, fmt.Errorf("contentdiscovery: encode announce: %w", err)
	}
	return SignedAnnounce{Announce: a, Signature: sk.Sign(b).Bytes()}, nil
}

type storeKey struct {
	hash   [blobs.HashSize]byte
	format byte
	kind   byte
	host   [key.PublicKeySize]byte
}

func makeStoreKey(content blobs.HashAndFormat, kind AnnounceKind, host key.EndpointID) (storeKey, error) {
	if content.Format > 255 {
		return storeKey{}, fmt.Errorf("contentdiscovery: unsupported blob format %d", content.Format)
	}
	if kind > 255 {
		return storeKey{}, fmt.Errorf("contentdiscovery: unsupported announce kind %d", kind)
	}
	return storeKey{
		hash:   content.Hash.Bytes(),
		format: byte(content.Format),
		kind:   byte(kind),
		host:   host.Bytes(),
	}, nil
}

func (k storeKey) bytes() [storeKeySize]byte {
	var out [storeKeySize]byte
	copy(out[:32], k.hash[:])
	out[32] = k.format
	out[33] = k.kind
	copy(out[34:], k.host[:])
	return out
}
