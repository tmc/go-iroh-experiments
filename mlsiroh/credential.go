package mlsiroh

import (
	"bytes"
	"errors"
	"fmt"
	"time"

	"github.com/tmc/go-iroh/key"
	"github.com/tmc/mls"
	"github.com/tmc/mls/multicred"
)

// Suite is the MLS cipher suite an mlsiroh credential is published
// under. It signs with Ed25519, which is what lets an iroh endpoint
// key stand as the credential key.
const Suite = mls.X25519AES128GCMSHA256Ed25519

// Errors reported by the package. They are distinguished because each
// names a different way a message can fail to be what mlsiroh expects,
// and a directory that cannot say which is hard to debug.
var (
	// ErrNotIrohCredential reports a credential that is not a weak
	// multi-credential, or not one holding a single binding of an
	// iroh endpoint.
	ErrNotIrohCredential = errors.New("mlsiroh: not an iroh:ed25519 credential")

	// ErrBindingCount reports a credential holding other than one
	// binding. See Verify.
	ErrBindingCount = errors.New("mlsiroh: credential must hold exactly one binding")

	// ErrIdentityMismatch reports a binding whose identity is not
	// its own credential key, so that the endpoint it names is not
	// the endpoint that signed it.
	ErrIdentityMismatch = errors.New("mlsiroh: binding identity is not its credential key")

	// ErrLeafKeyIsEndpointKey reports a leaf whose signature key is
	// the endpoint key itself. Such a leaf cannot rotate.
	ErrLeafKeyIsEndpointKey = errors.New("mlsiroh: leaf signature key is the endpoint key")

	// ErrWrongEndpoint reports a key package, group info, or
	// connection bound to an endpoint other than the one expected.
	ErrWrongEndpoint = errors.New("mlsiroh: wrong endpoint")

	// ErrWrongGroup reports a group info for a group other than the
	// one requested.
	ErrWrongGroup = errors.New("mlsiroh: group info names a different group")

	// ErrInvalidGroupInfo reports a group info that lacks an extension
	// mlsiroh needs, names a signer that is not a leaf of its own
	// tree, or whose signature does not verify.
	ErrInvalidGroupInfo = errors.New("mlsiroh: invalid group info")

	// ErrConsumed reports a key package that has already been served,
	// or that shares its init key with one that has.
	ErrConsumed = errors.New("mlsiroh: key package already consumed")
)

// Credential returns the weak multi-credential that binds leafKey,
// a leaf node signature key, to the endpoint sk names. The binding is
// signed by sk, so a verifier that has authenticated the endpoint has
// authenticated the leaf key.
//
// leafKey must not be the endpoint's own key: the point of the
// binding is that the leaf key can be rotated while the endpoint
// identity stays put. Call Credential again with the new key to
// rotate.
func Credential(sk key.SecretKey, leafKey mls.SignaturePublicKey) (mls.Credential, error) {
	id := sk.Public()
	idBytes := id.Bytes()
	if bytes.Equal(leafKey, idBytes[:]) {
		return mls.Credential{}, ErrLeafKeyIsEndpointKey
	}
	b := multicred.Binding{
		CipherSuite: Suite,
		Credential: mls.Credential{
			Type:     mls.CredentialTypeBasic,
			Identity: idBytes[:],
		},
		CredentialKey: idBytes[:],
	}
	// SignWithLabel takes the Ed25519 seed, not the expanded
	// private key, so this is sk.Bytes and not sk.Ed25519.
	seed := sk.Bytes()
	if err := b.Sign(seed[:], leafKey); err != nil {
		return mls.Credential{}, fmt.Errorf("mlsiroh: signing binding: %w", err)
	}
	return mls.Credential{
		Type: multicred.TypeWeakMulti,
		Body: &multicred.Credential{Bindings: []multicred.Binding{b}},
	}, nil
}

// Capabilities returns the capabilities an mlsiroh member must
// advertise. Every member of an mlsiroh group carries a weak
// multi-credential, so every member must list that credential type;
// RFC 9420, Section 7.3, rejects an Add otherwise.
//
// The list deliberately holds that one credential type and no other,
// which closes an mlsiroh group to members that are not endpoints.
// That is the package invariant: every leaf resolves to an endpoint
// you can dial, and [VerifyLeaf] never returns "this member is not
// one of ours". A group that must also admit plain basic credentials
// has to list mls.CredentialTypeBasic here, and it has to do so
// before the group exists: RFC 9420, Section 7.3, checks the
// capabilities of the joiner and of every existing member, both
// directions, so a group that did not plan for basic credentials
// cannot accept one however the joiner advertises itself. Retrofitting
// it costs a GroupContextExtensions or Update churn across the whole
// membership.
func Capabilities() mls.Capabilities {
	return mls.Capabilities{
		Versions:     []mls.ProtocolVersion{mls.Version10},
		CipherSuites: []mls.CipherSuite{Suite},
		Credentials:  []mls.CredentialType{multicred.TypeWeakMulti},
	}
}

// binding returns the single binding of an mlsiroh credential,
// checking the shape that mls cannot check for us: the credential
// type, the binding count, the inner credential type, and that the
// identity is the credential key.
func binding(c mls.Credential) (*multicred.Binding, error) {
	if c.Type != multicred.TypeWeakMulti {
		return nil, fmt.Errorf("%w: credential type %d", ErrNotIrohCredential, c.Type)
	}
	body, ok := c.Body.(*multicred.Credential)
	if !ok || body == nil {
		return nil, fmt.Errorf("%w: body is %T", ErrNotIrohCredential, c.Body)
	}
	if len(body.Bindings) != 1 {
		return nil, fmt.Errorf("%w: %d bindings", ErrBindingCount, len(body.Bindings))
	}
	b := &body.Bindings[0]
	if b.CipherSuite != Suite {
		return nil, fmt.Errorf("%w: binding cipher suite %d", ErrNotIrohCredential, b.CipherSuite)
	}
	if b.Credential.Type != mls.CredentialTypeBasic {
		return nil, fmt.Errorf("%w: inner credential type %d", ErrNotIrohCredential, b.Credential.Type)
	}
	if len(b.CredentialKey) != key.PublicKeySize {
		return nil, fmt.Errorf("%w: credential key is %d bytes", ErrNotIrohCredential, len(b.CredentialKey))
	}
	if !bytes.Equal(b.Credential.Identity, b.CredentialKey) {
		return nil, ErrIdentityMismatch
	}
	return b, nil
}

// Sign signs kp for publication: the binding in its credential with
// sk, and the leaf node and key package with leafPriv, the private
// half of kp.LeafNode.SignatureKey.
//
// Sign replaces kp.LeafNode.Credential, so a caller need not build
// one; it does not touch kp.LeafNode.Capabilities, which must already
// admit the credential type. See Capabilities.
func Sign(sk key.SecretKey, leafPriv []byte, kp *mls.KeyPackage) error {
	cred, err := Credential(sk, kp.LeafNode.SignatureKey)
	if err != nil {
		return err
	}
	kp.LeafNode.Credential = cred
	// A leaf node published in a key package is signed without a
	// group, so the group ID and leaf index do not enter it.
	if err := kp.LeafNode.Sign(kp.CipherSuite, leafPriv, nil, 0); err != nil {
		return fmt.Errorf("mlsiroh: signing leaf node: %w", err)
	}
	if err := kp.Sign(leafPriv); err != nil {
		return fmt.Errorf("mlsiroh: signing key package: %w", err)
	}
	return nil
}

// Verify checks kp against the iroh:ed25519 binding and returns the
// endpoint it names: the cipher suite, the credential shape, the
// binding signature, the leaf node and key package signatures, the
// leaf node rules of RFC 9420, Section 7.3, and the lifetime against
// now. A zero now skips the lifetime check.
//
// The shape checks are not redundant with multicred.Credential.Verify,
// which checks signatures only: nothing in package multicred knows
// that an iroh binding must name an endpoint. A binding can be
// cryptographically valid and still name an identity its signer does
// not hold.
func Verify(kp *mls.KeyPackage, now time.Time) (key.EndpointID, error) {
	if kp.CipherSuite != Suite {
		return key.EndpointID{}, fmt.Errorf("mlsiroh: key package cipher suite %d, want %d", kp.CipherSuite, Suite)
	}
	b, err := binding(kp.LeafNode.Credential)
	if err != nil {
		return key.EndpointID{}, err
	}
	if bytes.Equal(kp.LeafNode.SignatureKey, b.CredentialKey) {
		return key.EndpointID{}, ErrLeafKeyIsEndpointKey
	}
	// Validate covers both signatures, the leaf node source, the
	// capabilities, and the lifetime.
	if err := kp.Validate(now); err != nil {
		return key.EndpointID{}, fmt.Errorf("mlsiroh: %w", err)
	}
	if err := b.Verify(kp.LeafNode.SignatureKey); err != nil {
		return key.EndpointID{}, fmt.Errorf("mlsiroh: binding signature: %w", err)
	}
	return key.EndpointIDFromSlice(b.CredentialKey)
}

// VerifyLeaf checks the binding of a leaf node that arrived in a group
// rather than a key package and returns the endpoint it names: the
// credential shape and the binding signature over the leaf's
// signature key.
//
// That is all it checks. It does not verify the leaf node's own
// signature, its capabilities, or its lifetime, which MLS checks when
// the leaf enters the group; a leaf taken from a tree that mls has
// accepted has passed them. A leaf from anywhere else proves only that
// its endpoint once bound its signature key.
//
// A leaf installed by a commit carries the credential of the leaf it
// replaces, so the binding survives every commit untouched: RFC 9420
// gives a commit no way to change a leaf signature key. Rotating one
// is an Update proposal whose leaf node the member builds itself, and
// the binding it needs is [SignUpdate].
func VerifyLeaf(leaf *mls.LeafNode) (key.EndpointID, error) {
	b, err := binding(leaf.Credential)
	if err != nil {
		return key.EndpointID{}, err
	}
	if bytes.Equal(leaf.SignatureKey, b.CredentialKey) {
		return key.EndpointID{}, ErrLeafKeyIsEndpointKey
	}
	if err := b.Verify(leaf.SignatureKey); err != nil {
		return key.EndpointID{}, fmt.Errorf("mlsiroh: binding signature: %w", err)
	}
	return key.EndpointIDFromSlice(b.CredentialKey)
}

// NewClient returns an MLS client whose identity is the endpoint sk
// names, with a key package valid from now until now plus lifetime.
//
// It is [mls.NewClient] with the iroh:ed25519 binding applied: the
// client's leaf signature key is generated by mls and is not the
// endpoint key, and the credential binds the two. Publish the returned
// client's key package with [Directory.Add].
//
// SameIdentity compares endpoint identities, so branching and
// reinitialization preserve membership when leaf signature keys change.
func NewClient(sk key.SecretKey, lifetime time.Duration) (*mls.Client, error) {
	// The credential covers the leaf signature key, which does not
	// exist until mls has generated it, so the client is built with
	// a placeholder and then signed. The placeholder's type is the
	// real one, which is what makes mls derive the capabilities
	// Capabilities describes without being told them.
	c, err := mls.NewClient(Suite, mls.Credential{Type: multicred.TypeWeakMulti, Body: new(multicred.Credential)}, lifetime)
	if err != nil {
		return nil, fmt.Errorf("mlsiroh: %w", err)
	}
	if err := Sign(sk, c.SignaturePriv, c.KeyPackage); err != nil {
		return nil, err
	}
	c.SameIdentity = sameIdentity
	// The current mls API no longer offers a ValidateCredential hook for
	// application credential checks. The iroh:ed25519 binding is verified
	// at every entry point instead: Directory.Add rejects key packages
	// whose binding fails, and Session verifies every leaf it admits
	// through checkRoster and the Accept/Commit/Handle/Receive paths.
	return c, nil
}

// sameIdentity compares endpoint keys. MLS verifies the credential bindings
// against their leaf signature keys separately.
func sameIdentity(a, b *mls.Credential) bool {
	if a == nil || b == nil {
		return false
	}
	x, err := binding(*a)
	if err != nil {
		return false
	}
	y, err := binding(*b)
	return err == nil && bytes.Equal(x.CredentialKey, y.CredentialKey)
}

// SignUpdate fills in and signs leaf for an Update proposal that
// rotates the member's leaf signature key: it sets the source, the
// capabilities and a fresh binding of leaf.SignatureKey to the
// endpoint sk names, then signs the leaf with leafPriv, the private
// half of that key. groupID and index are the member's own, which a
// leaf node installed in a group is signed over.
//
// The caller supplies the new keys, because mls generates them:
// Suite.GenerateSignatureKeyPair for the signature key and
// Suite.GenerateKeyPair for leaf.EncryptionKey, which an Update must
// also change. The endpoint key does not change, which is the whole
// point: every other member resolves the rotated leaf to the same
// endpoint it resolved the old one to.
//
// Send the result with [mls.Group.ProposeUpdateKeys], which retains
// both private keys so that the proposer can follow its own rotation
// and sign with the new leaf's key once the commit that carries it is
// applied; a plain [mls.Group.Propose] does not, and the commit that
// applies the update then fails for the member that asked for it. The
// member proposing is never the member committing: RFC 9420, Section
// 12.2, forbids a committer from carrying its own Update.
func SignUpdate(sk key.SecretKey, leafPriv []byte, leaf *mls.LeafNode, groupID []byte, index mls.LeafIndex) error {
	cred, err := Credential(sk, leaf.SignatureKey)
	if err != nil {
		return err
	}
	leaf.Source = mls.LeafNodeSourceUpdate
	leaf.Lifetime = mls.Lifetime{}
	leaf.Capabilities = Capabilities()
	leaf.Credential = cred
	if err := leaf.Sign(Suite, leafPriv, groupID, index); err != nil {
		return fmt.Errorf("mlsiroh: signing update leaf node: %w", err)
	}
	return nil
}

// Leaves returns the indices, in order, of every leaf of t that
// [VerifyLeaf] resolves to id. Leaves of t that are blank, or that do
// not carry an mlsiroh binding, are skipped.
//
// It returns more than one index when an endpoint holds multiple leaves.
// JoinExternal removes a prior leaf only when its signature key matches
// the joiner's. With a fresh signature key, the endpoint joins beside
// its stale leaf. Use Leaves to identify those leaves and have the
// group's committer remove them. JoinExternal does not accept arbitrary
// Remove proposals; SameIdentity does not change how it finds a prior leaf.
func Leaves(t mls.RatchetTree, id key.EndpointID) []mls.LeafIndex {
	var found []mls.LeafIndex
	for i := mls.LeafIndex(0); i < t.Size(); i++ {
		leaf := t.Leaf(i)
		if leaf == nil {
			continue
		}
		got, err := VerifyLeaf(leaf)
		if err != nil {
			continue
		}
		if got.Equal(id) {
			found = append(found, i)
		}
	}
	return found
}

// verifyGroupInfo checks info's signature against the leaf it names in
// its own ratchet_tree, and returns the endpoint that leaf is bound to.
func verifyGroupInfo(info *mls.GroupInfo) (key.EndpointID, error) {
	var tree mls.RatchetTree
	if ok, err := info.Extensions.Decode(mls.ExtensionTypeRatchetTree, &tree); err != nil {
		return key.EndpointID{}, fmt.Errorf("%w: ratchet_tree extension: %w", ErrInvalidGroupInfo, err)
	} else if !ok {
		return key.EndpointID{}, fmt.Errorf("%w: no ratchet_tree extension", ErrInvalidGroupInfo)
	}
	leaf := tree.Leaf(mls.LeafIndex(info.Signer))
	if leaf == nil {
		return key.EndpointID{}, fmt.Errorf("%w: signer %d is not a leaf", ErrInvalidGroupInfo, info.Signer)
	}
	id, err := VerifyLeaf(leaf)
	if err != nil {
		return key.EndpointID{}, fmt.Errorf("mlsiroh: group info signer: %w", err)
	}
	if err := info.Verify(leaf.SignatureKey); err != nil {
		return key.EndpointID{}, fmt.Errorf("%w: signature: %w", ErrInvalidGroupInfo, err)
	}
	return id, nil
}
