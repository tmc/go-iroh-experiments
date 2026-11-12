package mlsiroh

import (
	"github.com/tmc/go-iroh/key"
	"github.com/tmc/mls"
	"sync"
	"testing"
	"time"
)

func sessionPair(t *testing.T) (*Session, *mls.Client, key.SecretKey) {
	t.Helper()
	a, err := key.GenerateSecretKey()
	if err != nil {
		t.Fatal(err)
	}
	b, err := key.GenerateSecretKey()
	if err != nil {
		t.Fatal(err)
	}
	ac, err := NewClient(a, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	bc, err := NewClient(b, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	g, err := ac.NewGroup([]byte(t.Name()), nil)
	if err != nil {
		t.Fatal(err)
	}
	s, err := NewSession(g)
	if err != nil {
		t.Fatal(err)
	}
	return s, bc, b
}

func TestSessionAdmission(t *testing.T) {
	owner, client, sk := sessionPair(t)
	a, err := owner.Reserve(sk.Public().EndpointID(), time.Now().Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := owner.Commit(nil); err == nil {
		t.Fatal("local commit during reservation")
	}
	if _, err := owner.Reserve(a.Endpoint, a.Expires); err == nil {
		t.Fatal("competing admission")
	}
	var tree mls.RatchetTree
	if ok, err := a.Info.Extensions.Decode(mls.ExtensionTypeRatchetTree, &tree); err != nil || !ok {
		t.Fatalf("tree: %v", err)
	}
	provisional, commit, err := client.JoinExternal(a.Info, tree, nil)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := mls.Marshal(commit)
	if err != nil {
		t.Fatal(err)
	}
	wrong := a.Token
	wrong[0] ^= 1
	if _, err := owner.Accept(wrong, a.Endpoint, wire); err == nil {
		t.Fatal("wrong reservation accepted")
	}
	receipt, err := owner.Accept(a.Token, a.Endpoint, wire)
	if err != nil {
		t.Fatal(err)
	}
	if !receipt.Matches(provisional, wire) {
		t.Fatal("receipt mismatch")
	}
	if receipt.Matches(provisional, append(wire, 0)) {
		t.Fatal("receipt matched different bytes")
	}
	if _, err := owner.Accept(a.Token, a.Endpoint, wire); err == nil {
		t.Fatal("admission accepted twice")
	}
	member, err := NewSession(provisional)
	if err != nil {
		t.Fatal(err)
	}
	proposal, err := member.Rotate(sk)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := owner.Handle(proposal); err != nil {
		t.Fatal(err)
	}
	accepted, _, err := owner.Commit(nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := member.Handle(accepted); err != nil {
		t.Fatal(err)
	}
	message, err := member.Protect([]byte("rotated"))
	if err != nil {
		t.Fatal(err)
	}
	content, err := owner.Handle(message)
	if err != nil {
		t.Fatal(err)
	}
	if string(content.Content.ApplicationData) != "rotated" {
		t.Fatal("wrong plaintext")
	}
}

func TestSessionReservationExpiry(t *testing.T) {
	owner, _, sk := sessionPair(t)
	if _, err := owner.Reserve(sk.Public().EndpointID(), time.Now().Add(-time.Second)); err == nil {
		t.Fatal("expired reservation")
	}
	a, err := owner.Reserve(sk.Public().EndpointID(), time.Now().Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	// Control the clock boundary without a sleep.
	owner.pending.Expires = time.Now().Add(-time.Second)
	if _, err := owner.Accept(a.Token, a.Endpoint, nil); err == nil {
		t.Fatal("expired admission accepted")
	}
	if _, _, err := owner.Commit(nil); err != nil {
		t.Fatal(err)
	}
}

func TestSessionConcurrentReservations(t *testing.T) {
	owner, _, sk := sessionPair(t)
	var wg sync.WaitGroup
	accepted := make(chan bool, 16)
	for range 16 {
		wg.Go(func() {
			_, err := owner.Reserve(sk.Public().EndpointID(), time.Now().Add(time.Minute))
			accepted <- err == nil
		})
	}
	wg.Wait()
	close(accepted)
	n := 0
	for ok := range accepted {
		if ok {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("accepted %d reservations, want 1", n)
	}
}

func TestSessionReceive(t *testing.T) {
	owner, client, sk := sessionPair(t)
	a, err := owner.Reserve(sk.Public().EndpointID(), time.Now().Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	var tree mls.RatchetTree
	if ok, err := a.Info.Extensions.Decode(mls.ExtensionTypeRatchetTree, &tree); err != nil || !ok {
		t.Fatal("tree")
	}
	g, commit, err := client.JoinExternal(a.Info, tree, nil)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := mls.Marshal(commit)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := owner.Accept(a.Token, a.Endpoint, wire); err != nil {
		t.Fatal(err)
	}
	member, err := NewSession(g)
	if err != nil {
		t.Fatal(err)
	}
	other, err := key.GenerateSecretKey()
	if err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct {
		name string
		from key.EndpointID
		kind mls.ContentType
	}{
		{"wrong kind", a.Endpoint, mls.ContentTypeProposal},
		{"wrong endpoint", other.Public().EndpointID(), mls.ContentTypeApplication},
	} {
		t.Run(tt.name, func(t *testing.T) {
			m, err := member.Protect([]byte("message"))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := owner.Receive(tt.from, m, tt.kind); err == nil {
				t.Fatal("unexpected acceptance")
			}
		})
	}
	m, err := member.Protect([]byte("still usable"))
	if err != nil {
		t.Fatal(err)
	}
	c, err := owner.Receive(a.Endpoint, m, mls.ContentTypeApplication)
	if err != nil {
		t.Fatal(err)
	}
	if string(c.Content.ApplicationData) != "still usable" {
		t.Fatal("wrong content")
	}
}
