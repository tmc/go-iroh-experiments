package irciroh

import "testing"

func TestFold(t *testing.T) {
	for _, tt := range []struct{ in, want string }{
		{"", ""},
		{"#go", "#go"},
		{"#Go", "#go"},
		{"TMC", "tmc"},
		// The Scandinavian half of rfc1459, which is the half a
		// ToLower gets wrong and the half an impersonation hides in.
		{"tmc[1]", "tmc{1}"},
		{"tmc{1}", "tmc{1}"},
		{`a\b`, "a|b"},
		{"a|b", "a|b"},
		{"~x", "^x"},
		{"^x", "^x"},
		// Casemapping is ASCII: a name is not folded into another
		// script's idea of the same letter, which is the direction a
		// lookalike would want it folded.
		{"É", "É"},
	} {
		if got := Fold(tt.in); got != tt.want {
			t.Errorf("Fold(%q) = %q, want %q", tt.in, got, tt.want)
		}
		if got := Fold(tt.want); got != tt.want {
			t.Errorf("Fold(%q) = %q, want it unchanged", tt.want, got)
		}
	}
}
