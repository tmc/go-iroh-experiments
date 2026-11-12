package main

import (
	"bytes"
	"context"
	"encoding/json"
	"github.com/tmc/go-iroh/iroh"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tmc/go-iroh-experiments/mlsiroh"
	"github.com/tmc/go-iroh/key"
	"github.com/tmc/mls"
)

func TestLostResponses(t *testing.T) {
	a, err := key.GenerateSecretKey()
	if err != nil {
		t.Fatal(err)
	}
	b, err := key.GenerateSecretKey()
	if err != nil {
		t.Fatal(err)
	}
	ac, err := mlsiroh.NewClient(a, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	bc, err := mlsiroh.NewClient(b, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	g, err := ac.NewGroup([]byte(t.Name()), nil)
	if err != nil {
		t.Fatal(err)
	}
	owner, err := mlsiroh.NewSession(g)
	if err != nil {
		t.Fatal(err)
	}
	admission, err := owner.Reserve(b.Public().EndpointID(), time.Now().Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	var tree mls.RatchetTree
	if ok, err := admission.Info.Extensions.Decode(mls.ExtensionTypeRatchetTree, &tree); err != nil || !ok {
		t.Fatal("tree")
	}
	joined, commit, err := bc.JoinExternal(admission.Info, tree, nil)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := mls.Marshal(commit)
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	state := &ownerState{session: owner, member: b.Public().EndpointID(), token: admission.Token, out: &out}
	join := chatRequest{Op: "join", Token: admission.Token, Wire: wire}
	lost := state.process(join)
	replayed := state.process(join)
	if lost.Error != "" || replayed.Receipt == nil || !replayed.Receipt.Matches(joined, wire) {
		t.Fatalf("join retry: %+v", replayed)
	}
	if strings.Count(out.String(), "member joined") != 1 {
		t.Fatal("join applied twice")
	}
	member, err := mlsiroh.NewSession(joined)
	if err != nil {
		t.Fatal(err)
	}
	message, err := member.Protect([]byte("once"))
	if err != nil {
		t.Fatal(err)
	}
	wire, err = mls.Marshal(message)
	if err != nil {
		t.Fatal(err)
	}
	req := chatRequest{Seq: 1, Op: "message", Wire: wire}
	first := state.process(req)
	second := state.process(req)
	if first.Error != "" || !reflect.DeepEqual(first, second) {
		t.Fatal("message retry differs")
	}
	if strings.Count(out.String(), "member: once") != 1 {
		t.Fatal("message displayed twice")
	}
	proposal, err := member.Rotate(b)
	if err != nil {
		t.Fatal(err)
	}
	wire, err = mls.Marshal(proposal)
	if err != nil {
		t.Fatal(err)
	}
	req = chatRequest{Seq: 2, Op: "rotate", Wire: wire}
	first = state.process(req)
	second = state.process(req)
	if first.Error != "" || !reflect.DeepEqual(first, second) || len(second.Events) != 1 {
		t.Fatalf("rotation retry: %+v", second)
	}
	if len(state.events) != 1 {
		t.Fatal("rotation committed twice")
	}
	var accepted mls.Message
	if err := mls.Unmarshal(second.Events[0].Wire, &accepted); err != nil {
		t.Fatal(err)
	}
	if _, err := member.Handle(&accepted); err != nil {
		t.Fatal(err)
	}
	reply, err := owner.Protect([]byte("retained while disconnected"))
	if err != nil {
		t.Fatal(err)
	}
	wire, err = mls.Marshal(reply)
	if err != nil {
		t.Fatal(err)
	}
	state.enqueue(wire)
	polled := state.process(chatRequest{Seq: 3, Ack: 1, Op: "poll"})
	if len(polled.Events) != 1 || polled.Events[0].ID != 2 {
		t.Fatalf("ordered resume: %+v", polled)
	}
	if err := mls.Unmarshal(polled.Events[0].Wire, &accepted); err != nil {
		t.Fatal(err)
	}
	content, err := member.Handle(&accepted)
	if err != nil {
		t.Fatal(err)
	}
	if string(content.Content.ApplicationData) != "retained while disconnected" {
		t.Fatal("wrong message")
	}
	_ = state.process(chatRequest{Seq: 4, Ack: 2, Op: "poll"})
	if len(state.events) != 0 {
		t.Fatal("acknowledged events retained")
	}

	// Lose a real stream response after the request was processed. The member
	// opens another connection and resends the exact ciphertext and sequence.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	ep, err := iroh.Bind(ctx, iroh.WithSecretKey(a), iroh.WithBindAddr(netip.MustParseAddrPort("127.0.0.1:0")))
	if err != nil {
		t.Fatal(err)
	}
	defer ep.Shutdown(context.Background())
	peer, err := iroh.Bind(ctx, iroh.WithSecretKey(b), iroh.WithBindAddr(netip.MustParseAddrPort("127.0.0.1:0")))
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Shutdown(context.Background())
	var dropped atomic.Bool
	handler := iroh.ProtocolHandlerFunc(func(ctx context.Context, c *iroh.Conn) error {
		select {
		case <-c.HandshakeComplete():
		case <-ctx.Done():
			return ctx.Err()
		}
		if !c.RemoteID().Equal(state.member) {
			return mlsiroh.ErrWrongEndpoint
		}
		st, err := c.AcceptStream(ctx)
		if err != nil {
			return err
		}
		defer st.Close()
		if err := st.SetDeadline(deadline(ctx)); err != nil {
			return err
		}
		var request chatRequest
		if err := readJSON(st, &request); err != nil {
			return err
		}
		state.mu.Lock()
		result := state.process(request)
		state.mu.Unlock()
		if dropped.CompareAndSwap(false, true) {
			return st.CloseWrite()
		}
		if err := json.NewEncoder(st).Encode(result); err != nil {
			return err
		}
		return st.CloseWrite()
	})
	router, err := iroh.NewRouter(ep, map[string]iroh.ProtocolHandler{chatALPN: handler}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer router.Shutdown(context.Background())
	message, err = member.Protect([]byte("network retry once"))
	if err != nil {
		t.Fatal(err)
	}
	wire, err = mls.Marshal(message)
	if err != nil {
		t.Fatal(err)
	}
	result, err := retry(ctx, peer, ep.Addr(), chatRequest{Seq: 5, Ack: 2, Op: "message", Wire: wire}, io.Discard)
	if err != nil || result.Error != "" {
		t.Fatalf("network retry: %v, %s", err, result.Error)
	}
	state.mu.Lock()
	displayed := strings.Count(out.String(), "member: network retry once")
	state.mu.Unlock()
	if displayed != 1 {
		t.Fatalf("displayed %d times", displayed)
	}
}

func TestIdentityFile(t *testing.T) {
	name := filepath.Join(t.TempDir(), "key")
	first, err := loadKey(name)
	if err != nil {
		t.Fatal(err)
	}
	second, err := loadKey(name)
	if err != nil {
		t.Fatal(err)
	}
	if !first.Public().EndpointID().Equal(second.Public().EndpointID()) {
		t.Fatal("identity changed")
	}
	stat, err := os.Stat(name)
	if err != nil {
		t.Fatal(err)
	}
	if stat.Mode().Perm() != 0600 {
		t.Fatalf("key permissions: %v", stat.Mode())
	}
}
