package mlsiroh

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"
	"time"

	"github.com/tmc/go-iroh/key"
	"github.com/tmc/mls"
	"github.com/tmc/mls/multicred"
)

// newKeyPackage returns a key package published by sk, together with
// the private half of its leaf signature key.
func newKeyPackage(t *testing.T, sk key.SecretKey) (*mls.KeyPackage, []byte) {
	t.Helper()
	seed := make([]byte, ed25519.SeedSize)
	if _, err := rand.Read(seed); err != nil {
		t.Fatal(err)
	}
	leafPub := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)

	initPriv, initPub, err := Suite.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	_ = initPriv
	_, encPub, err := Suite.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	kp := &mls.KeyPackage{
		Version:     mls.Version10,
		CipherSuite: Suite,
		InitKey:     initPub,
		LeafNode: mls.LeafNode{
			EncryptionKey: encPub,
			SignatureKey:  mls.SignaturePublicKey(leafPub),
			Capabilities:  Capabilities(),
			Source:        mls.LeafNodeSourceKeyPackage,
			Lifetime: mls.Lifetime{
				NotBefore: uint64(now.Add(-time.Minute).Unix()),
				NotAfter:  uint64(now.Add(time.Hour).Unix()),
			},
		},
	}
	if err := Sign(sk, seed, kp); err != nil {
		t.Fatal(err)
	}
	return kp, seed
}

func TestCredentialRoundTrip(t *testing.T) {
	sk, err := key.GenerateSecretKey()
	if err != nil {
		t.Fatal(err)
	}
	kp, _ := newKeyPackage(t, sk)

	got, err := Verify(kp, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if want := sk.Public().EndpointID(); !got.Equal(want) {
		t.Fatalf("Verify = %v, want %v", got, want)
	}

	// The same credential must survive the wire.
	b, err := mls.Marshal(kp)
	if err != nil {
		t.Fatal(err)
	}
	var kp2 mls.KeyPackage
	if err := mls.Unmarshal(b, &kp2); err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(&kp2, time.Now()); err != nil {
		t.Fatalf("after round trip: %v", err)
	}
}

func TestCredentialRejects(t *testing.T) {
	sk, err := key.GenerateSecretKey()
	if err != nil {
		t.Fatal(err)
	}
	other, err := key.GenerateSecretKey()
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name string
		mung func(*mls.KeyPackage)
		want error
	}{
		{
			name: "basic credential",
			mung: func(kp *mls.KeyPackage) {
				id := sk.Public().Bytes()
				kp.LeafNode.Credential = mls.Credential{Type: mls.CredentialTypeBasic, Identity: id[:]}
			},
			want: ErrNotIrohCredential,
		},
		{
			name: "no bindings",
			mung: func(kp *mls.KeyPackage) {
				kp.LeafNode.Credential.Body = &multicred.Credential{}
			},
			want: ErrBindingCount,
		},
		{
			name: "two bindings",
			mung: func(kp *mls.KeyPackage) {
				c := kp.LeafNode.Credential.Body.(*multicred.Credential)
				c.Bindings = append(c.Bindings, c.Bindings[0])
			},
			want: ErrBindingCount,
		},
		{
			name: "identity is not the credential key",
			mung: func(kp *mls.KeyPackage) {
				c := kp.LeafNode.Credential.Body.(*multicred.Credential)
				id := other.Public().Bytes()
				c.Bindings[0].Credential.Identity = id[:]
			},
			want: ErrIdentityMismatch,
		},
		{
			name: "binding lifted to another leaf",
			mung: func(kp *mls.KeyPackage) {
				// A binding signed for one leaf key must not
				// verify against a different one.
				victim, _ := newKeyPackage(t, sk)
				kp.LeafNode.Credential = victim.LeafNode.Credential
			},
			want: nil, // any error; the signature must fail
		},
		{
			name: "wrong cipher suite",
			mung: func(kp *mls.KeyPackage) {
				kp.CipherSuite = mls.P256AES128GCMSHA256P256
			},
			want: nil, // the credential may be fine; the key package is not
		},
		{
			name: "missing weak-multi capability",
			mung: func(kp *mls.KeyPackage) {
				kp.LeafNode.Capabilities.Credentials = []mls.CredentialType{mls.CredentialTypeBasic}
			},
			want: nil, // mls reports ErrUnsupportedCapability
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			kp, _ := newKeyPackage(t, sk)
			tt.mung(kp)
			_, err := Verify(kp, time.Now())
			if err == nil {
				t.Fatal("Verify accepted a bad key package")
			}
			if tt.want != nil && !errors.Is(err, tt.want) {
				t.Fatalf("Verify = %v, want %v", err, tt.want)
			}
		})
	}
}

func TestCredentialExpired(t *testing.T) {
	sk, err := key.GenerateSecretKey()
	if err != nil {
		t.Fatal(err)
	}
	kp, _ := newKeyPackage(t, sk)
	if _, err := Verify(kp, time.Now().Add(2*time.Hour)); !errors.Is(err, mls.ErrExpired) {
		t.Fatalf("Verify of an expired package = %v, want ErrExpired", err)
	}
	// A zero time skips the lifetime check, which is what a
	// receiver does: RFC 9420, Section 7.3.
	if _, err := Verify(kp, time.Time{}); err != nil {
		t.Fatalf("Verify with a zero time = %v", err)
	}
}

// TestCredentialRotation rotates a member's leaf signature key in a
// real group: bob builds an Update proposal with SignUpdate, alice
// commits it, and alice still resolves bob's leaf to bob's endpoint.
// That is the property the binding exists for - the leaf key is not
// the identity - and nothing but a group can show it, because an
// Update leaf node is signed over the group id and the leaf index.
func TestCredentialRotation(t *testing.T) {
	alice, aliceID := newRotationClient(t)
	bob, bobID := newRotationClient(t)

	g, err := alice.NewGroup([]byte("rotation"), nil)
	if err != nil {
		t.Fatal(err)
	}
	next, _, welcome, err := g.Commit([]*mls.Proposal{{
		Type: mls.ProposalTypeAdd,
		Add:  &mls.Add{KeyPackage: *bob.KeyPackage},
	}})
	if err != nil {
		t.Fatal(err)
	}
	bg, err := bob.Join(welcome.Welcome, next.Tree.Clone())
	if err != nil {
		t.Fatal(err)
	}

	before := next.Tree.Leaf(bg.Index)
	if before == nil {
		t.Fatalf("no leaf at bob's index %d", bg.Index)
	}
	oldKey := before.SignatureKey

	// Bob mints the two keys an Update must change and asks mlsiroh
	// for the binding. The endpoint key does not move.
	sigPriv, sigPub, err := Suite.GenerateSignatureKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	encPriv, encPub, err := Suite.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	leaf := *before
	leaf.SignatureKey = sigPub
	leaf.EncryptionKey = encPub
	if err := SignUpdate(bob.sk, sigPriv, &leaf, bg.Context.GroupID, bg.Index); err != nil {
		t.Fatal(err)
	}

	// Bob sends it as a proposal and alice commits it by reference.
	// RFC 9420, Section 12.2, forbids a committer from carrying its
	// own Update inline, which is the shape a rotation has to take:
	// the member rotating is not the member committing.
	msg, err := bg.ProposeUpdateKeys(&leaf, encPriv, sigPriv)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := next.Handle(msg); err != nil {
		t.Fatalf("alice receiving bob's update: %v", err)
	}
	after, commit, _, err := next.Commit(nil)
	if err != nil {
		t.Fatalf("committing bob's update: %v", err)
	}

	got := after.Tree.Leaf(bg.Index)
	if got == nil {
		t.Fatalf("no leaf at bob's index %d after the update", bg.Index)
	}
	if bytes.Equal(got.SignatureKey, oldKey) {
		t.Fatal("the update did not change the leaf signature key")
	}
	id, err := VerifyLeaf(got)
	if err != nil {
		t.Fatal(err)
	}
	if !id.Equal(bobID) {
		t.Fatalf("rotated leaf resolves to %v, want bob %v", id, bobID)
	}
	// And alice is still alice.
	if id, err := VerifyLeaf(after.Tree.Leaf(next.Index)); err != nil || !id.Equal(aliceID) {
		t.Fatalf("alice's leaf = %v, %v, want %v", id, err, aliceID)
	}

	// Bob follows his own rotation: he can apply the commit that
	// installed his new leaf, and read what alice says after it.
	bobAfter, _, err := bg.Handle(commit)
	if err != nil {
		t.Fatalf("bob applying the commit that rotated him: %v", err)
	}
	sealed, err := after.Protect(nil, []byte("still you"))
	if err != nil {
		t.Fatal(err)
	}
	content, err := bobAfter.Unprotect(sealed)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(content.Content.ApplicationData); got != "still you" {
		t.Fatalf("bob read %q", got)
	}
}

// TestLeaves finds the leaves an endpoint holds, which is what an
// external rejoiner needs so it does not join beside its own stale
// leaf. See Leaves.
func TestLeaves(t *testing.T) {
	alice, aliceID := newRotationClient(t)
	bob, bobID := newRotationClient(t)

	g, err := alice.NewGroup([]byte("leaves"), nil)
	if err != nil {
		t.Fatal(err)
	}
	next, _, _, err := g.Commit([]*mls.Proposal{{
		Type: mls.ProposalTypeAdd,
		Add:  &mls.Add{KeyPackage: *bob.KeyPackage},
	}})
	if err != nil {
		t.Fatal(err)
	}

	for _, tt := range []struct {
		name string
		id   key.EndpointID
		want int
	}{
		{"alice", aliceID, 1},
		{"bob", bobID, 1},
		{"a stranger", newEndpointID(t), 0},
	} {
		if got := Leaves(next.Tree, tt.id); len(got) != tt.want {
			t.Errorf("Leaves(%s) = %v, want %d", tt.name, got, tt.want)
		}
	}
}

// newRotationClient returns a client and the endpoint it is bound to,
// without an endpoint: a client needs only the secret key.
func newRotationClient(t *testing.T) (*rotationClient, key.EndpointID) {
	t.Helper()
	sk, err := key.GenerateSecretKey()
	if err != nil {
		t.Fatal(err)
	}
	c, err := NewClient(sk, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	return &rotationClient{Client: c, sk: sk}, sk.Public().EndpointID()
}

type rotationClient struct {
	*mls.Client
	sk key.SecretKey
}

func newEndpointID(t *testing.T) key.EndpointID {
	t.Helper()
	sk, err := key.GenerateSecretKey()
	if err != nil {
		t.Fatal(err)
	}
	return sk.Public().EndpointID()
}

// TestVerifyLeafRejects covers the ways a leaf's binding can fail.
func TestVerifyLeafRejects(t *testing.T) {
	sk, err := key.GenerateSecretKey()
	if err != nil {
		t.Fatal(err)
	}
	other, err := key.GenerateSecretKey()
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name string
		mung func(*mls.LeafNode)
		want error
	}{
		{
			name: "basic credential",
			mung: func(l *mls.LeafNode) {
				id := sk.Public().Bytes()
				l.Credential = mls.Credential{Type: mls.CredentialTypeBasic, Identity: id[:]}
			},
			want: ErrNotIrohCredential,
		},
		{
			name: "two bindings",
			mung: func(l *mls.LeafNode) {
				c := l.Credential.Body.(*multicred.Credential)
				c.Bindings = append(c.Bindings, c.Bindings[0])
			},
			want: ErrBindingCount,
		},
		{
			name: "identity is not the credential key",
			mung: func(l *mls.LeafNode) {
				id := other.Public().Bytes()
				l.Credential.Body.(*multicred.Credential).Bindings[0].Credential.Identity = id[:]
			},
			want: ErrIdentityMismatch,
		},
		{
			name: "leaf key is the endpoint key",
			mung: func(l *mls.LeafNode) {
				id := sk.Public().Bytes()
				l.SignatureKey = id[:]
			},
			want: ErrLeafKeyIsEndpointKey,
		},
		{
			name: "binding lifted to another leaf",
			mung: func(l *mls.LeafNode) {
				victim, _ := newKeyPackage(t, sk)
				l.Credential = victim.LeafNode.Credential
			},
			want: nil, // any error; the signature must fail
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			kp, _ := newKeyPackage(t, sk)
			leaf := kp.LeafNode
			tt.mung(&leaf)
			_, err := VerifyLeaf(&leaf)
			if err == nil {
				t.Fatal("VerifyLeaf accepted a bad leaf")
			}
			if tt.want != nil && !errors.Is(err, tt.want) {
				t.Fatalf("VerifyLeaf = %v, want %v", err, tt.want)
			}
		})
	}
}

func TestCredentialLeafKeyIsEndpointKey(t *testing.T) {
	sk, err := key.GenerateSecretKey()
	if err != nil {
		t.Fatal(err)
	}
	id := sk.Public().Bytes()
	if _, err := Credential(sk, mls.SignaturePublicKey(id[:])); !errors.Is(err, ErrLeafKeyIsEndpointKey) {
		t.Fatalf("Credential = %v, want ErrLeafKeyIsEndpointKey", err)
	}
}

// Fresh leaf keys must preserve endpoint identity through Branch, Reinitialize, and Resume.
func TestFreshLeafKeys(t *testing.T) {
	newClient := func(sk key.SecretKey) *mls.Client {
		t.Helper()
		c, err := NewClient(sk, time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	aliceKey, err := key.GenerateSecretKey()
	if err != nil {
		t.Fatal(err)
	}
	bobKey, err := key.GenerateSecretKey()
	if err != nil {
		t.Fatal(err)
	}
	alice, bob := newClient(aliceKey), newClient(bobKey)
	g, err := alice.NewGroup([]byte("original"), nil)
	if err != nil {
		t.Fatal(err)
	}
	g, _, welcome, err := g.Commit([]*mls.Proposal{{Type: mls.ProposalTypeAdd, Add: &mls.Add{KeyPackage: *bob.KeyPackage}}})
	if err != nil {
		t.Fatal(err)
	}
	oldBob, err := bob.Join(welcome.Welcome, g.Tree)
	if err != nil {
		t.Fatal(err)
	}
	freshBob := newClient(bobKey)
	branch, welcome, err := g.Branch([]byte("branch"), nil, []*mls.KeyPackage{freshBob.KeyPackage})
	if err != nil {
		t.Fatal(err)
	}
	resumed, err := freshBob.Resume(welcome.Welcome, branch.Tree, oldBob)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(branch.EpochAuthenticator(), resumed.EpochAuthenticator()) {
		t.Fatal("branch epoch authenticators differ")
	}
	msg, err := branch.Protect(nil, []byte("fresh leaf"))
	if err != nil {
		t.Fatal(err)
	}
	content, err := resumed.Unprotect(msg)
	if err != nil {
		t.Fatal(err)
	}
	if string(content.Content.ApplicationData) != "fresh leaf" {
		t.Fatal("branch message differs")
	}

	// Reinitialization changes both members' leaf keys.
	finished, commit, _, err := g.Commit([]*mls.Proposal{{
		Type:   mls.ProposalTypeReinit,
		Reinit: &mls.Reinit{GroupID: []byte("successor"), Version: mls.Version10, CipherSuite: Suite},
	}})
	if err != nil {
		t.Fatal(err)
	}
	finishedBob, _, err := oldBob.Handle(commit)
	if err != nil {
		t.Fatal(err)
	}
	freshAlice, freshBob := newClient(aliceKey), newClient(bobKey)
	successor, welcome, err := finished.Reinitialize(freshAlice, []*mls.KeyPackage{freshBob.KeyPackage})
	if err != nil {
		t.Fatal(err)
	}
	resumed, err = freshBob.Resume(welcome.Welcome, successor.Tree, finishedBob)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(successor.EpochAuthenticator(), resumed.EpochAuthenticator()) {
		t.Fatal("successor epoch authenticators differ")
	}

}

func TestSameIdentity(t *testing.T) {
	sk, err := key.GenerateSecretKey()
	if err != nil {
		t.Fatal(err)
	}
	other, err := key.GenerateSecretKey()
	if err != nil {
		t.Fatal(err)
	}
	a, _ := newKeyPackage(t, sk)
	fresh, _ := newKeyPackage(t, sk)
	different, _ := newKeyPackage(t, other)
	tests := []struct {
		name       string
		credential *mls.Credential
		want       bool
	}{
		{"same credential", &a.LeafNode.Credential, true},
		{"fresh leaf key", &fresh.LeafNode.Credential, true},
		{"different endpoint", &different.LeafNode.Credential, false},
		{"nil", nil, false},
		{"basic", &mls.Credential{Type: mls.CredentialTypeBasic}, false},
		{"empty binding", &mls.Credential{Type: multicred.TypeWeakMulti, Body: new(multicred.Credential)}, false},
		{"nil body", &mls.Credential{Type: multicred.TypeWeakMulti, Body: (*multicred.Credential)(nil)}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := sameIdentity(&a.LeafNode.Credential, tt.credential); got != tt.want {
				t.Errorf("sameIdentity = %v, want %v", got, tt.want)
			}
			if got := sameIdentity(tt.credential, &a.LeafNode.Credential); got != tt.want {
				t.Errorf("reversed sameIdentity = %v, want %v", got, tt.want)
			}
		})
	}
}
