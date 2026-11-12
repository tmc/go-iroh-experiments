package irciroh

import (
	"bytes"
	"context"
	"encoding/binary"
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/tmc/go-iroh-experiments/mlsiroh"
	"github.com/tmc/go-iroh/key"
	"github.com/tmc/go-iroh/netaddr"
	"github.com/tmc/go-iroh/postcard"
	"github.com/tmc/mls"
)

// fuzzKey is the key every fuzz seed is signed with.
var fuzzKey = key.NewSecretKey([32]byte{7: 1})

// signedSeed returns a well-formed envelope signed against domain.
func signedSeed(f *testing.F, domain [32]byte, k kind, nick, text string) []byte {
	f.Helper()
	e, err := sign(fuzzKey, domain, k, 1, nick, text)
	if err != nil {
		f.Fatal(err)
	}
	b, err := e.encode()
	if err != nil {
		f.Fatal(err)
	}
	return b
}

// FuzzDecode checks that decode never panics and that what it accepts
// is exactly what encode would send.
func FuzzDecode(f *testing.F) {
	for _, k := range []kind{kindJoin, kindMessage, kindTopic, kindRank} {
		f.Add(signedSeed(f, testDomain, k, "alice", "hello"))
	}
	f.Add(signedSeed(f, testDomain, kindMessage, "", string(bytes.Repeat([]byte("x"), 3000))))
	f.Add([]byte{})
	f.Add([]byte{wireVersion})
	f.Fuzz(func(t *testing.T, b []byte) {
		e, err := decode(b, testDomain)
		if err != nil {
			return
		}
		if err := checkLine(e.Nick, e.Text); err != nil {
			t.Fatalf("decode accepted a line checkLine refuses: %v", err)
		}
		out, err := e.encode()
		if err != nil {
			t.Fatalf("decoded envelope does not encode: %v", err)
		}
		if !bytes.Equal(out, b) {
			t.Fatalf("decode accepted a non-canonical encoding\n in %x\nout %x", b, out)
		}
	})
}

// FuzzParseTicket checks that ParseTicket never panics and that a ticket
// it accepts survives a round trip.
func FuzzParseTicket(f *testing.F) {
	f.Add(Ticket{Channel: "#go"}.String())
	f.Add(Ticket{Channel: "#secret", Secret: []byte("hunter2"), Founder: fuzzKey.Public().EndpointID()}.String())
	peer := netaddr.NewEndpointAddr(fuzzKey.Public().EndpointID()).WithIP(netip.AddrPortFrom(netip.IPv6Loopback(), 4001))
	f.Add(Ticket{Channel: "#go", Peers: []netaddr.EndpointAddr{peer}}.String())
	f.Add(TicketKind)
	f.Add(TicketKind + "AAAA")
	f.Fuzz(func(t *testing.T, s string) {
		tk, err := ParseTicket(s)
		if err != nil {
			return
		}
		if _, err := checkChannel(tk.Channel); err != nil {
			t.Fatalf("ParseTicket accepted channel %q: %v", tk.Channel, err)
		}
		again, err := ParseTicket(tk.String())
		if err != nil {
			t.Fatalf("ParseTicket(%q).String() does not parse: %v", s, err)
		}
		if again.Channel != tk.Channel || !bytes.Equal(again.Secret, tk.Secret) || again.Founder != tk.Founder || len(again.Peers) != len(tk.Peers) {
			t.Fatalf("round trip changed the ticket: %+v -> %+v", tk, again)
		}
	})
}

// FuzzDecodeNote checks the plaintext of a sealed message.
func FuzzDecodeNote(f *testing.F) {
	for _, n := range []note{
		{Version: noteVersion, Kind: uint8(kindMessage), Seq: 1, Time: time.Now().UnixMilli(), Nick: "alice", Text: "hi"},
		{Version: noteVersion, Kind: uint8(kindTopic), Seq: 1 << 40, Time: -1, Text: "topic"},
		{Version: noteVersion - 1},
	} {
		b, err := postcard.Marshal(n)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(b)
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		n, err := decodeNote(b)
		if err != nil {
			return
		}
		if n.Version != noteVersion || checkLine(n.Nick, n.Text) != nil {
			t.Fatalf("decodeNote accepted %+v", n)
		}
	})
}

// FuzzHistoryResponse checks what a node does with a recall answer: the
// answer is parsed, and each line it serves is checked for replay.
func FuzzHistoryResponse(f *testing.F) {
	line := signedSeed(f, testDomain, kindMessage, "alice", "said")
	for _, lines := range [][][]byte{nil, {line}, {line, line, []byte("junk")}} {
		b, err := postcard.Marshal(historyResponse{Version: historyVersion, Lines: lines})
		if err != nil {
			f.Fatal(err)
		}
		f.Add(b)
	}
	now := time.Now()
	f.Fuzz(func(t *testing.T, b []byte) {
		lines, err := decodeHistoryResponse(b)
		if err != nil {
			return
		}
		for _, l := range lines {
			e, ok := replayable(l, testDomain, now)
			if !ok {
				continue
			}
			if k := kind(e.Kind); k != kindMessage && k != kindNotice {
				t.Fatalf("replayable accepted kind %d", k)
			}
		}
	})
}

// FuzzHistoryRequest checks the serving side of recall.
func FuzzHistoryRequest(f *testing.F) {
	for _, req := range []historyRequest{
		{Version: historyVersion, Channel: "#busy", Limit: 10},
		{Version: historyVersion, Channel: "#busy", Limit: 1<<32 - 1},
		{Version: historyVersion + 1},
	} {
		b, err := postcard.Marshal(req)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(b)
	}
	h := historyHandler{node: &Node{}, serving: make(chan struct{}, maxRecallServing)}
	f.Fuzz(func(t *testing.T, b []byte) {
		s := &testStream{Reader: bytes.NewReader(b)}
		if err := h.serve(s); err != nil {
			t.Fatal(err)
		}
		if _, err := decodeHistoryResponse(s.out.Bytes()); err != nil {
			t.Fatalf("served an answer that does not parse: %v", err)
		}
	})
}

// fuzzKeyPackage returns a key package bound to sk, in the form an
// invite request carries it.
func fuzzKeyPackage(f *testing.F, sk key.SecretKey) (*mls.Client, []byte) {
	f.Helper()
	c, err := mlsiroh.NewClient(sk, time.Hour)
	if err != nil {
		f.Fatal(err)
	}
	b, err := mls.Marshal(&mls.Message{Version: mls.Version10, WireFormat: mls.WireFormatKeyPackage, KeyPackage: c.KeyPackage})
	if err != nil {
		f.Fatal(err)
	}
	return c, b
}

// FuzzInviteRequest checks what a founder does with an invite request
// before it commits anything: parse it, then parse and verify the key
// package it carries.
func FuzzInviteRequest(f *testing.F) {
	_, kp := fuzzKeyPackage(f, fuzzKey)
	for _, req := range []inviteRequest{
		{Version: inviteVersion, Channel: "#sealed", Secret: []byte("secret"), KeyPackage: kp},
		{Version: inviteVersion, Channel: "#sealed", KeyPackage: kp[:len(kp)/2]},
		{Version: inviteVersion + 1},
	} {
		b, err := postcard.Marshal(req)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(b)
	}
	now := time.Now()
	f.Fuzz(func(t *testing.T, b []byte) {
		req, err := decodeInviteRequest(b)
		if err != nil {
			return
		}
		kp, id, err := verifyKeyPackage(req.KeyPackage, now)
		if err != nil {
			return
		}
		if got, err := mlsiroh.Verify(kp, now); err != nil || got != id {
			t.Fatalf("verifyKeyPackage named %v, Verify says %v, %v", id, got, err)
		}
	})
}

// FuzzInviteResponse checks what a joiner does with a founder's answer
// before it hands the Welcome to MLS.
func FuzzInviteResponse(f *testing.F) {
	founder, _ := fuzzKeyPackage(f, fuzzKey)
	g, err := founder.NewGroup([]byte("#sealed"), nil)
	if err != nil {
		f.Fatal(err)
	}
	joiner, _ := fuzzKeyPackage(f, key.NewSecretKey([32]byte{7: 2}))
	next, _, w, err := g.Commit([]*mls.Proposal{{Type: mls.ProposalTypeAdd, Add: &mls.Add{KeyPackage: *joiner.KeyPackage}}})
	if err != nil {
		f.Fatal(err)
	}
	wb, err := mls.Marshal(&mls.Message{Version: mls.Version10, WireFormat: mls.WireFormatWelcome, Welcome: w.Welcome})
	if err != nil {
		f.Fatal(err)
	}
	tree := next.Tree.Clone()
	tb, err := mls.Marshal(&tree)
	if err != nil {
		f.Fatal(err)
	}
	for _, resp := range []inviteResponse{
		{Version: inviteVersion, OK: true, Welcome: wb, Tree: tb},
		{Version: inviteVersion, OK: true, Welcome: wb[:len(wb)/2], Tree: tb},
		{Version: inviteVersion},
	} {
		b, err := postcard.Marshal(resp)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(b)
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		resp, err := decodeInviteResponse(b)
		if err != nil || !resp.OK {
			return
		}
		_, _, _ = resp.welcome()
	})
}

// FuzzPrivateFrame checks the receiving side of a private message: the
// frame, the envelope in it, and the reply.
func FuzzPrivateFrame(f *testing.F) {
	frame := func(b []byte) []byte { return append(binary.BigEndian.AppendUint32(nil, uint32(len(b))), b...) }
	good := signedSeed(f, dmDomain, kindMessage, "alice", "psst")
	f.Add(frame(good))
	f.Add(frame(good)[:10])
	f.Add([]byte{0, 0, 0, 0})
	f.Add([]byte{0xff, 0xff, 0xff, 0xff})
	f.Add(append(frame(good), frame(good)...))
	peer := fuzzKey.Public().EndpointID()
	ctx, cancel := context.WithCancel(context.Background())
	f.Cleanup(cancel)
	f.Fuzz(func(t *testing.T, b []byte) {
		n := &Node{ctx: ctx, private: make(chan Event, 1), dmSeen: make(dmReplay)}
		s := &testStream{Reader: bytes.NewReader(b)}
		err := dmHandler{n}.serve(peer, s)
		reply := s.out.Bytes()
		if len(reply) > 1 {
			t.Fatalf("replied %x to one frame", reply)
		}
		if err == nil && !slices.Equal(reply, []byte{ack}) {
			t.Fatalf("served a frame and replied %x", reply)
		}
		if err == nil {
			ev := <-n.private
			if checkLine(ev.From.Nick, ev.Text) != nil {
				t.Fatalf("delivered %q from %q", ev.Text, ev.From.Nick)
			}
		}
	})
}

// FuzzReadFrame checks that a frame length never allocates more than
// [MaxEnvelopeSize].
func FuzzReadFrame(f *testing.F) {
	f.Add([]byte{0, 0, 0, 3, 'a', 'b', 'c'})
	f.Add([]byte{0, 0, 0x10, 0x01})
	f.Fuzz(func(t *testing.T, b []byte) {
		buf, err := readFrame(bytes.NewReader(b))
		if err == nil && (len(buf) == 0 || len(buf) > MaxEnvelopeSize) {
			t.Fatalf("readFrame returned %d bytes", len(buf))
		}
	})
}
