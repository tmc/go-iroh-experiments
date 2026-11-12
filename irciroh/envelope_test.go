package irciroh

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/tmc/go-iroh/key"
)

// testDomain is the topic the tests sign against. Which one it is does
// not matter; that there is one does - see [envelope.signed].
var testDomain = [32]byte{'i', 'r', 'c', 'i', 'r', 'o', 'h', '/', 't', 'e', 's', 't'}

// testKey returns a deterministic secret key for tests.
func testKey(t *testing.T, seed byte) key.SecretKey {
	t.Helper()
	var b [32]byte
	for i := range b {
		b[i] = seed
	}
	return key.NewSecretKey(b)
}

func TestEnvelopeRoundTrip(t *testing.T) {
	sk := testKey(t, 1)
	tests := []struct {
		name string
		kind kind
		nick string
		text string
	}{
		{"join", kindJoin, "alice", ""},
		{"message", kindMessage, "alice", "hello, #test"},
		{"notice", kindNotice, "alice", "away"},
		{"topic", kindTopic, "alice", "release planning"},
		{"nick", kindNick, "bob", "bob"},
		{"unicode", kindMessage, "älice", "héllo ✨"},
		{"long", kindMessage, "alice", strings.Repeat("x", 3000)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e, err := sign(sk, testDomain, tt.kind, 7, tt.nick, tt.text)
			if err != nil {
				t.Fatal(err)
			}
			b, err := e.encode()
			if err != nil {
				t.Fatal(err)
			}
			got, err := decode(b, testDomain)
			if err != nil {
				t.Fatal(err)
			}
			if got != e {
				t.Fatalf("decode round trip changed the envelope")
			}
			if got.sender() != sk.Public().EndpointID() {
				t.Errorf("sender = %v, want %v", got.sender(), sk.Public().EndpointID())
			}
			if kind(got.Kind) != tt.kind || got.Nick != tt.nick || got.Text != tt.text {
				t.Errorf("got kind %d nick %q text %q", got.Kind, got.Nick, got.Text)
			}
		})
	}
}

func TestEnvelopeDecodeErrors(t *testing.T) {
	sk := testKey(t, 2)
	good, err := sign(sk, testDomain, kindMessage, 1, "alice", "hello")
	if err != nil {
		t.Fatal(err)
	}
	goodBytes, err := good.encode()
	if err != nil {
		t.Fatal(err)
	}

	tamper := func(f func(e *envelope)) []byte {
		e := good
		f(&e)
		b, err := e.encode()
		if err != nil {
			t.Fatal(err)
		}
		return b
	}

	tests := []struct {
		name string
		in   []byte
		want error
	}{
		{"truncated", goodBytes[:len(goodBytes)-1], nil},
		{"trailing", append(append([]byte(nil), goodBytes...), 0), nil},
		{"text tampered", tamper(func(e *envelope) { e.Text = "goodbye" }), errSignature},
		{"nick tampered", tamper(func(e *envelope) { e.Nick = "mallory" }), errSignature},
		{"seq tampered", tamper(func(e *envelope) { e.Seq = 99 }), errSignature},
		{"time tampered", tamper(func(e *envelope) { e.Time += 1000 }), errSignature},
		{"signature cleared", tamper(func(e *envelope) { e.Sig = [64]byte{} }), errSignature},
		{"bad version", tamper(func(e *envelope) { e.Version = 2 }), errVersion},
		{"oversize", make([]byte, MaxEnvelopeSize+1), ErrTooLarge},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := decode(tt.in, testDomain)
			if err == nil {
				t.Fatal("decode succeeded, want error")
			}
			if tt.want != nil && !errors.Is(err, tt.want) {
				t.Fatalf("decode error = %v, want %v", err, tt.want)
			}
		})
	}
}

func TestEnvelopeTooLarge(t *testing.T) {
	sk := testKey(t, 3)
	if _, err := sign(sk, testDomain, kindMessage, 1, "alice", strings.Repeat("x", MaxEnvelopeSize)); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("seal error = %v, want %v", err, ErrTooLarge)
	}
}

func TestSeqSetAccept(t *testing.T) {
	sk := testKey(t, 4)
	from := sk.Public().EndpointID()
	now := time.Now()
	at := func(seq uint64, offset time.Duration) envelope {
		return envelope{Seq: seq, Time: now.Add(offset).UnixMilli()}
	}

	tests := []struct {
		name string
		send []envelope
		want []bool
	}{
		{"increasing", []envelope{at(1, 0), at(2, 0), at(3, 0)}, []bool{true, true, true}},
		{"replay", []envelope{at(5, 0), at(5, 0)}, []bool{true, false}},
		{"reorder", []envelope{at(5, 0), at(4, 0), at(6, 0)}, []bool{true, true, true}},
		{"reorder replayed", []envelope{at(5, 0), at(4, 0), at(4, 0), at(5, 0)}, []bool{true, true, false, false}},
		{"gap filled late", []envelope{at(10, 0), at(12, 0), at(11, 0), at(11, 0)}, []bool{true, true, true, false}},
		{"edge of window", []envelope{at(100, 0), at(100-replayWindow+1, 0)}, []bool{true, true}},
		{"below window", []envelope{at(100, 0), at(100-replayWindow, 0)}, []bool{true, false}},
		{"jump clears window", []envelope{at(1, 0), at(1+2*replayWindow, 0), at(1+2*replayWindow-1, 0), at(1, 0)}, []bool{true, true, true, false}},
		{"window survives a shift", []envelope{at(1, 0), at(3, 0), at(1, 0)}, []bool{true, true, false}},
		{"skew ahead", []envelope{at(1, 10*time.Minute)}, []bool{false}},
		{"skew within", []envelope{at(1, time.Minute)}, []bool{true}},
		{"skew behind within", []envelope{at(1, -time.Minute)}, []bool{true}},
		{"skew behind", []envelope{at(1, -time.Hour)}, []bool{false}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := make(seqSet)
			for i, e := range tt.send {
				if got := s.accept(from, e, now); got != tt.want[i] {
					t.Errorf("accept(seq %d) = %v, want %v", e.Seq, got, tt.want[i])
				}
			}
		})
	}
}

// An envelope names no channel, so the only thing keeping a line said in
// one channel from being presented as a line said in another is that the
// topic is bound into the signature. This is that check.
func TestSignatureBindsTheTopic(t *testing.T) {
	sk := key.NewSecretKey([32]byte{1})
	here := [32]byte{'h', 'e', 'r', 'e'}
	there := [32]byte{'t', 'h', 'e', 'r', 'e'}
	e, err := sign(sk, here, kindMessage, 1, "alice", "the launch code is 1234")
	if err != nil {
		t.Fatal(err)
	}
	b, err := e.encode()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := decode(b, here); err != nil {
		t.Errorf("decode in the channel it was said in: %v", err)
	}
	if _, err := decode(b, there); !errors.Is(err, errSignature) {
		t.Errorf("decode in another channel = %v, want %v", err, errSignature)
	}
}

func TestCheckLine(t *testing.T) {
	tests := []struct {
		name string
		nick string
		text string
		ok   bool
	}{
		{"plain", "alice", "hello", true},
		{"empty", "", "", true},
		{"unicode", "älice", "héllo ✨", true},
		{"formatting", "alice", "\x02bold\x02 \x0304red\x03 \x1ditalic\x1d \x1funder\x1f \x1estrike\x1e \x16rev\x16 \x0freset", true},
		{"ctcp action", "alice", "\x01ACTION waves\x01", true},
		{"topic mark", "alice", topicMark + "a topic", true},
		{"text CRLF", "alice", "hi\r\nPRIVMSG #x :pwned", false},
		{"text CR", "alice", "hi\rthere", false},
		{"text LF", "alice", "hi\nthere", false},
		{"text NUL", "alice", "hi\x00", false},
		{"text tab", "alice", "a\tb", true},
		{"text tabs", "alice", "\tcol1\tcol2\t", true},
		{"text bell", "alice", "\x07", false},
		{"text escape", "alice", "\x1b[31mred", false},
		{"text DEL", "alice", "a\x7f", false},
		{"text C1", "alice", "a\u0085b", false},
		{"text C1 CSI", "alice", "\u009b31m", false},
		{"text above C1", "alice", " nbsp", true},
		{"nick space", "al ice", "hi", false},
		{"nick tab", "al\tice", "hi", false},
		{"nick CRLF", "alice\r\n", "hi", false},
		{"nick bold", "\x02alice", "hi", false},
		{"nick ctcp", "\x01alice", "hi", false},
		{"nick DEL", "alice\x7f", "hi", false},
		{"nick C1", "alice\u0090", "hi", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := checkLine(tt.nick, tt.text)
			if (err == nil) != tt.ok {
				t.Fatalf("checkLine(%q, %q) = %v, want ok %v", tt.nick, tt.text, err, tt.ok)
			}
			if err != nil && !errors.Is(err, ErrControl) {
				t.Fatalf("checkLine error = %v, want %v", err, ErrControl)
			}
		})
	}
}

// forge signs an envelope without the checks sign makes, as a peer
// running other code could.
func forge(t *testing.T, sk key.SecretKey, domain [32]byte, k kind, seq uint64, nick, text string) []byte {
	t.Helper()
	e := envelope{
		Version: wireVersion,
		Kind:    uint8(k),
		Sender:  sk.Public().Bytes(),
		Seq:     seq,
		Time:    time.Now().UnixMilli(),
		Nick:    nick,
		Text:    text,
	}
	msg, err := e.signed(domain)
	if err != nil {
		t.Fatal(err)
	}
	e.Sig = sk.Sign(msg).Bytes()
	b, err := e.encode()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestControlCharactersRefused checks both ends: sign will not produce
// an envelope carrying a line break, and decode will not accept one a
// peer produced anyway, though it accepts a tab in text.
func TestControlCharactersRefused(t *testing.T) {
	sk := testKey(t, 5)
	if _, err := sign(sk, testDomain, kindMessage, 1, "alice", "hi\r\nQUIT"); !errors.Is(err, ErrControl) {
		t.Errorf("sign with CRLF in text = %v, want %v", err, ErrControl)
	}
	if _, err := sign(sk, testDomain, kindNick, 1, "al\nice", ""); !errors.Is(err, ErrControl) {
		t.Errorf("sign with LF in nick = %v, want %v", err, ErrControl)
	}
	if err := (&Node{}).SetNick("al ice"); !errors.Is(err, ErrControl) {
		t.Errorf("SetNick with a space = %v, want %v", err, ErrControl)
	}
	for _, b := range [][]byte{
		forge(t, sk, testDomain, kindMessage, 1, "alice", "hi\r\nQUIT"),
		forge(t, sk, testDomain, kindMessage, 1, "al\nice", "hi"),
		forge(t, sk, testDomain, kindMessage, 1, "al\tice", "hi"),
	} {
		if _, err := decode(b, testDomain); !errors.Is(err, ErrControl) {
			t.Errorf("decode = %v, want %v", err, ErrControl)
		}
	}
	e, err := decode(forge(t, sk, testDomain, kindMessage, 1, "alice", "a\tb"), testDomain)
	if err != nil || e.Text != "a\tb" {
		t.Errorf("decode with a tab in text = %q, %v, want %q, nil", e.Text, err, "a\tb")
	}
}

// TestRefusedLineErrors checks that every call that sends a line refuses
// one it must not send with an error a caller can test for.
func TestRefusedLineErrors(t *testing.T) {
	if testing.Short() {
		t.Skip("network test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	n := newTestNode(t, ctx, "alice")
	pub, err := n.Join(ctx, "#lines", nil)
	if err != nil {
		t.Fatal(err)
	}
	room, _, err := n.Found(ctx, "#vault", nil)
	if err != nil {
		t.Fatal(err)
	}
	const bad = "hi\r\nQUIT"
	huge := strings.Repeat("x", MaxEnvelopeSize)
	self := n.Addr()
	tests := []struct {
		name string
		call func() error
		want error
	}{
		{"SetNick", func() error { return n.SetNick("al\nice") }, ErrControl},
		{"SendPrivate", func() error { return n.SendPrivate(ctx, self.ID, self, bad) }, ErrControl},
		{"SendPrivate huge", func() error { return n.SendPrivate(ctx, self.ID, self, huge) }, ErrTooLarge},
	}
	for _, c := range []*Channel{pub, room} {
		tests = append(tests, []struct {
			name string
			call func() error
			want error
		}{
			{c.Name() + " Say", func() error { return c.Say(ctx, bad) }, ErrControl},
			{c.Name() + " Notice", func() error { return c.Notice(ctx, bad) }, ErrControl},
			{c.Name() + " SetTopic", func() error { return c.SetTopic(ctx, bad) }, ErrControl},
			{c.Name() + " Part", func() error { return c.Part(ctx, bad) }, ErrControl},
			{c.Name() + " Say huge", func() error { return c.Say(ctx, huge) }, ErrTooLarge},
			{c.Name() + " SetTopic huge", func() error { return c.SetTopic(ctx, huge) }, ErrTooLarge},
		}...)
	}
	for _, tt := range tests {
		if err := tt.call(); !errors.Is(err, tt.want) {
			t.Errorf("%s = %v, want %v", tt.name, err, tt.want)
		}
	}
}
