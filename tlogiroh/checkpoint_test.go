package tlogiroh

import (
	"strings"
	"testing"

	"golang.org/x/mod/sumdb/tlog"
)

func TestCheckpointRoundTrip(t *testing.T) {
	want := Checkpoint{
		Origin: "example.org/log",
		Tree:   tlog.Tree{N: 42, Hash: tlog.RecordHash([]byte("x"))},
	}
	text, err := want.MarshalText()
	if err != nil {
		t.Fatal(err)
	}
	got, err := ParseCheckpoint(text)
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Errorf("round trip = %+v, want %+v", got, want)
	}
}

func TestCheckpointMarshalErrors(t *testing.T) {
	for _, tt := range []struct {
		name string
		c    Checkpoint
	}{
		{"empty origin", Checkpoint{}},
		{"newline origin", Checkpoint{Origin: "a\nb"}},
		{"negative size", Checkpoint{Origin: "a", Tree: tlog.Tree{N: -1}}},
	} {
		if _, err := tt.c.MarshalText(); err == nil {
			t.Errorf("%s: MarshalText succeeded, want error", tt.name)
		}
	}
}

func TestParseCheckpointErrors(t *testing.T) {
	hash := tlog.RecordHash([]byte("x")).String()
	for _, tt := range []struct {
		name, text string
	}{
		{"empty", ""},
		{"no final newline", "a\n1\n" + hash},
		{"two lines", "a\n1\n"},
		{"four lines", "a\n1\n" + hash + "\nextra\n"},
		{"empty origin", "\n1\n" + hash + "\n"},
		{"bad size", "a\nx\n" + hash + "\n"},
		{"negative size", "a\n-1\n" + hash + "\n"},
		{"leading zero size", "a\n01\n" + hash + "\n"},
		{"bad hash", "a\n1\nnot-base64!\n"},
	} {
		if _, err := ParseCheckpoint([]byte(tt.text)); err == nil {
			t.Errorf("%s: ParseCheckpoint(%q) succeeded, want error", tt.name, tt.text)
		}
	}
}

func TestParseCheckpointZero(t *testing.T) {
	c := Checkpoint{Origin: "example.org/log"}
	text, err := c.MarshalText()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(text), "\n0\n") {
		t.Fatalf("marshaled zero checkpoint = %q, want size line 0", text)
	}
	got, err := ParseCheckpoint(text)
	if err != nil {
		t.Fatal(err)
	}
	if got != c {
		t.Errorf("round trip = %+v, want %+v", got, c)
	}
}
