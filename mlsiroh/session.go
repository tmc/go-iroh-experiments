package mlsiroh

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"sync"
	"time"

	"github.com/tmc/go-iroh/key"
	"github.com/tmc/mls"
)

// Session serializes an in-memory group's operations. Its owner is the sole
// committer. Members submit proposals to that owner. Restart requires a fresh
// group incarnation; neither epoch state nor admission receipts are durable.
// The zero value is not usable. Do not access the supplied group after NewSession.
type Session struct {
	mu      sync.Mutex
	group   *mls.Group
	pending *Admission
}

// Admission reserves an epoch for one authenticated endpoint's external join.
// Treat Info as immutable. A reservation expires without accepting a commit.
type Admission struct {
	Token    [32]byte
	Endpoint key.EndpointID
	Expires  time.Time
	Info     *mls.GroupInfo
}

// Receipt identifies the exact commit accepted by the sole committer. A joiner
// must check the group ID, epoch, and hash before using its provisional group.
type Receipt struct {
	GroupID []byte
	Epoch   uint64
	Commit  [32]byte
}

// NewSession takes exclusive ownership of g, which must be non-nil.
func NewSession(g *mls.Group) (*Session, error) {
	if g == nil {
		return nil, errors.New("mlsiroh: nil group")
	}
	if g.CipherSuite != Suite {
		return nil, mls.ErrUnsupportedCipherSuite
	}
	if err := checkRoster(g); err != nil {
		return nil, err
	}
	return &Session{group: g}, nil
}

func (s *Session) reserved() bool {
	if s.pending != nil && !time.Now().Before(s.pending.Expires) {
		s.pending = nil
	}
	return s.pending != nil
}

// Reserve admits endpoint for an external join until expires. Authorization is
// the caller's responsibility. The returned snapshot is served only to endpoint;
// it must not be published as an unrestricted GroupInfo.
func (s *Session) Reserve(endpoint key.EndpointID, expires time.Time) (Admission, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.reserved() {
		return Admission{}, errors.New("mlsiroh: admission already reserved")
	}
	if !expires.After(time.Now()) {
		return Admission{}, errors.New("mlsiroh: admission expired")
	}
	info, err := s.group.GroupInfo()
	if err != nil {
		return Admission{}, err
	}
	a := Admission{Endpoint: endpoint, Expires: expires, Info: info.GroupInfo}
	if _, err := rand.Read(a.Token[:]); err != nil {
		return Admission{}, err
	}
	s.pending = &a
	return a, nil
}

// Accept accepts one external commit for a reservation. from must be the iroh
// connection's authenticated endpoint, never an endpoint claimed in its payload.
// A rejected attempt leaves the reservation active until its expiry.
func (s *Session) Accept(token [32]byte, from key.EndpointID, wire []byte) (Receipt, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.reserved() || s.pending.Token != token || !s.pending.Endpoint.Equal(from) {
		return Receipt{}, errors.New("mlsiroh: no matching admission")
	}
	var m mls.Message
	if err := mls.Unmarshal(wire, &m); err != nil {
		return Receipt{}, err
	}
	c, err := s.group.Unprotect(&m)
	if err != nil {
		return Receipt{}, err
	}
	if c.Content.ContentType != mls.ContentTypeCommit || c.Content.Sender.Type != mls.SenderTypeNewMemberCommit || c.Content.Commit.Path == nil {
		return Receipt{}, errors.New("mlsiroh: expected external commit")
	}
	id, err := VerifyLeaf(&c.Content.Commit.Path.LeafNode)
	if err != nil {
		return Receipt{}, err
	}
	if !id.Equal(from) {
		return Receipt{}, ErrWrongEndpoint
	}
	next, err := s.group.ApplyCommit(c)
	if err != nil {
		return Receipt{}, err
	}
	if err := checkRoster(next); err != nil {
		return Receipt{}, err
	}
	s.group = next
	s.pending = nil
	return Receipt{GroupID: bytes.Clone(next.Context.GroupID), Epoch: next.Epoch(), Commit: sha256.Sum256(wire)}, nil
}

// Commit applies local proposals unless an external admission holds the epoch.
func (s *Session) Commit(proposals []*mls.Proposal) (*mls.Message, *mls.Message, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.reserved() {
		return nil, nil, errors.New("mlsiroh: epoch reserved for admission")
	}
	next, commit, welcome, err := s.group.Commit(proposals)
	if err != nil {
		return nil, nil, err
	}
	if err := checkRoster(next); err != nil {
		return nil, nil, err
	}
	s.group = next
	return commit, welcome, nil
}

// Handle processes a sequenced message. An admission blocks competing commits;
// proposals and application messages can still be received. A sole committer
// uses Receive for messages from members, so those messages cannot apply commits.
func (s *Session) Handle(m *mls.Message) (*mls.AuthenticatedContent, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, err := s.group.Unprotect(m)
	if err != nil {
		return nil, err
	}
	return s.handle(c)
}

// Receive processes an application message or Update proposal from an
// authenticated endpoint. kind must be application or proposal. Commits and
// other proposals are rejected before they change the group; the owner alone
// creates commits. Rejected private messages may consume a receive ratchet.
func (s *Session) Receive(from key.EndpointID, m *mls.Message, kind mls.ContentType) (*mls.AuthenticatedContent, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if kind != mls.ContentTypeApplication && kind != mls.ContentTypeProposal {
		return nil, errors.New("mlsiroh: invalid receive kind")
	}
	c, err := s.group.Unprotect(m)
	if err != nil {
		return nil, err
	}
	if c.Content.ContentType != kind || c.Content.Sender.Type != mls.SenderTypeMember {
		return nil, errors.New("mlsiroh: unexpected member content")
	}
	if kind == mls.ContentTypeProposal && c.Content.Proposal.Type != mls.ProposalTypeUpdate {
		return nil, errors.New("mlsiroh: expected update proposal")
	}
	leaf := s.group.Tree.Leaf(mls.LeafIndex(c.Content.Sender.LeafIndex))
	if leaf == nil {
		return nil, mls.ErrLeafRange
	}
	id, err := VerifyLeaf(leaf)
	if err != nil {
		return nil, err
	}
	if !id.Equal(from) {
		return nil, ErrWrongEndpoint
	}
	return s.handle(c)
}

func (s *Session) handle(c *mls.AuthenticatedContent) (*mls.AuthenticatedContent, error) {
	var err error
	switch c.Content.ContentType {
	case mls.ContentTypeProposal:
		if c.Content.Proposal.Type == mls.ProposalTypeUpdate {
			old := s.group.Tree.Leaf(mls.LeafIndex(c.Content.Sender.LeafIndex))
			if old == nil {
				return nil, mls.ErrLeafRange
			}
			id, e := VerifyLeaf(old)
			if e != nil {
				return nil, e
			}
			newID, e := VerifyLeaf(&c.Content.Proposal.Update.LeafNode)
			if e != nil {
				return nil, e
			}
			if !id.Equal(newID) {
				return nil, ErrWrongEndpoint
			}
		}
		err = s.group.AddProposal(c)
	case mls.ContentTypeCommit:
		if s.reserved() {
			return nil, errors.New("mlsiroh: epoch reserved for admission")
		}
		var next *mls.Group
		next, err = s.group.ApplyCommit(c)
		if err == nil {
			err = checkRoster(next)
		}
		if err == nil {
			s.group = next
		}
	}
	return c, err
}

// Protect encrypts an application message in the accepted epoch.
func (s *Session) Protect(data []byte) (*mls.Message, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.group.Protect(nil, data)
}

// Matches reports whether a provisional join matches the accepted commit receipt.
func (r Receipt) Matches(g *mls.Group, wire []byte) bool {
	return bytes.Equal(g.Context.GroupID, r.GroupID) && g.Epoch() == r.Epoch && r.Commit == sha256.Sum256(wire)
}

// Rotate proposes fresh encryption and signing keys bound to sk. A different
// member must commit the proposal. The new signing key activates only when
// the member applies the commit that carries the proposal, so while the
// proposal is pending, rejected, or superseded the member keeps signing
// with the key the group knows.
func (s *Session) Rotate(sk key.SecretKey) (*mls.Message, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	id, err := VerifyLeaf(s.group.Tree.Leaf(s.group.Index))
	if err != nil {
		return nil, err
	}
	if !id.Equal(sk.Public().EndpointID()) {
		return nil, ErrWrongEndpoint
	}
	enc, pub, err := Suite.GenerateKeyPair()
	if err != nil {
		return nil, err
	}
	sig, sigPub, err := Suite.GenerateSignatureKeyPair()
	if err != nil {
		return nil, err
	}
	leaf := *s.group.Tree.Leaf(s.group.Index)
	leaf.EncryptionKey, leaf.SignatureKey = pub, sigPub
	if err := SignUpdate(sk, sig, &leaf, s.group.Context.GroupID, s.group.Index); err != nil {
		return nil, err
	}
	// ProposeUpdateKeys keeps both private halves with the proposal;
	// MLS installs them only when the commit that carries the proposal
	// is applied. The proposal itself is framed with the signing key
	// the group still knows.
	return s.group.ProposeUpdateKeys(&leaf, enc, sig)
}

func checkRoster(g *mls.Group) error {
	seen := make(map[key.EndpointID]bool)
	for _, leaf := range g.Tree.Members() {
		id, err := VerifyLeaf(leaf)
		if err != nil {
			return err
		}
		if seen[id] {
			return errors.New("mlsiroh: duplicate endpoint in session")
		}
		seen[id] = true
	}
	return nil
}
