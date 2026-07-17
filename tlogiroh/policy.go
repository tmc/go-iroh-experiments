package tlogiroh

import (
	"errors"
	"fmt"
	"strings"

	"golang.org/x/mod/sumdb/note"
)

// A Policy states what makes a signed checkpoint acceptable: the origin it
// must name, the operator key that must have signed it, and how many of the
// known witness keys must have cosigned it. The zero Policy is not usable;
// construct one with NewPolicy.
type Policy struct {
	origin    string
	operator  note.Verifier
	witnesses []note.Verifier
	k         int
}

// NewPolicy returns a policy requiring checkpoints named origin, signed by
// operator, and cosigned by at least k of the witnesses. origin must be
// non-empty and contain no newline, operator must be non-nil, and
// 0 <= k <= len(witnesses).
func NewPolicy(origin string, operator note.Verifier, witnesses []note.Verifier, k int) (Policy, error) {
	if origin == "" || strings.Contains(origin, "\n") {
		return Policy{}, fmt.Errorf("tlogiroh: invalid origin %q", origin)
	}
	if operator == nil {
		return Policy{}, errors.New("tlogiroh: nil operator verifier")
	}
	if k < 0 || k > len(witnesses) {
		return Policy{}, fmt.Errorf("tlogiroh: witness threshold %d out of range for %d witnesses", k, len(witnesses))
	}
	keys := map[string]bool{keyID(operator): true}
	for _, w := range witnesses {
		if w == nil {
			return Policy{}, errors.New("tlogiroh: nil witness verifier")
		}
		id := keyID(w)
		if keys[id] {
			return Policy{}, fmt.Errorf("tlogiroh: duplicate verifier key %s", w.Name())
		}
		keys[id] = true
	}
	return Policy{origin: origin, operator: operator, witnesses: witnesses, k: k}, nil
}

// Open verifies the signed checkpoint message against the policy and parses
// its text. It returns ErrOriginMismatch or ErrWitnessThreshold on policy
// failure, without consulting any stored head.
func (p Policy) Open(msg []byte) (Checkpoint, error) {
	if p.operator == nil {
		return Checkpoint{}, errors.New("tlogiroh: zero policy")
	}
	verifiers := make([]note.Verifier, 0, 1+len(p.witnesses))
	verifiers = append(verifiers, p.operator)
	verifiers = append(verifiers, p.witnesses...)
	n, err := note.Open(msg, note.VerifierList(verifiers...))
	if err != nil {
		return Checkpoint{}, fmt.Errorf("tlogiroh: open checkpoint: %w", err)
	}
	c, err := ParseCheckpoint([]byte(n.Text))
	if err != nil {
		return Checkpoint{}, err
	}
	if c.Origin != p.origin {
		return Checkpoint{}, fmt.Errorf("%w: checkpoint names %q, policy expects %q", ErrOriginMismatch, c.Origin, p.origin)
	}
	signed := make(map[string]bool, len(n.Sigs))
	for _, sig := range n.Sigs {
		signed[sigID(sig)] = true
	}
	if !signed[keyID(p.operator)] {
		return Checkpoint{}, fmt.Errorf("tlogiroh: checkpoint missing operator signature by %q", p.operator.Name())
	}
	cosigned := 0
	for _, w := range p.witnesses {
		if signed[keyID(w)] {
			cosigned++
		}
	}
	if cosigned < p.k {
		return Checkpoint{}, fmt.Errorf("%w: have %d, need %d", ErrWitnessThreshold, cosigned, p.k)
	}
	return c, nil
}

func keyID(v note.Verifier) string {
	return fmt.Sprintf("%s+%08x", v.Name(), v.KeyHash())
}

func sigID(sig note.Signature) string {
	return fmt.Sprintf("%s+%08x", sig.Name, sig.Hash)
}
