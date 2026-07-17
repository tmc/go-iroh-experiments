package tlogiroh

import (
	"encoding/binary"
	"errors"
	"fmt"

	"golang.org/x/mod/sumdb/note"
)

// An Equivocation proves a log operator signed two different tree heads of
// the same size: both messages verify against the operator key, name the
// same origin and tree size, and carry different root hashes.
type Equivocation struct {
	First  []byte // signed checkpoint note message
	Second []byte // conflicting signed checkpoint note message
}

// MarshalBinary encodes the proof for transmission or storage.
func (e Equivocation) MarshalBinary() ([]byte, error) {
	if len(e.First) == 0 || len(e.Second) == 0 {
		return nil, errors.New("tlogiroh: incomplete equivocation proof")
	}
	data := binary.AppendUvarint(nil, uint64(len(e.First)))
	data = append(data, e.First...)
	data = binary.AppendUvarint(data, uint64(len(e.Second)))
	data = append(data, e.Second...)
	return data, nil
}

// UnmarshalBinary decodes a proof encoded by MarshalBinary. It does not
// verify it; use VerifyEquivocation.
func (e *Equivocation) UnmarshalBinary(data []byte) error {
	first, rest, err := readUvarintBytes(data)
	if err != nil {
		return fmt.Errorf("tlogiroh: malformed equivocation proof: %w", err)
	}
	second, rest, err := readUvarintBytes(rest)
	if err != nil || len(rest) != 0 {
		return errors.New("tlogiroh: malformed equivocation proof")
	}
	e.First, e.Second = first, second
	return nil
}

func readUvarintBytes(data []byte) (chunk, rest []byte, err error) {
	n, size := binary.Uvarint(data)
	if size <= 0 || n > uint64(len(data)-size) {
		return nil, nil, errors.New("bad length prefix")
	}
	return data[size : size+int(n)], data[size+int(n):], nil
}

// VerifyEquivocation checks the proof and returns the equivocated tree
// size. It fails if either message does not verify against operator, the
// origins or sizes differ, or the root hashes are equal.
func VerifyEquivocation(e Equivocation, origin string, operator note.Verifier) (int64, error) {
	first, err := openOperatorCheckpoint(e.First, origin, operator)
	if err != nil {
		return 0, err
	}
	second, err := openOperatorCheckpoint(e.Second, origin, operator)
	if err != nil {
		return 0, err
	}
	if first.Tree.N != second.Tree.N {
		return 0, fmt.Errorf("tlogiroh: not an equivocation: tree sizes %d and %d differ", first.Tree.N, second.Tree.N)
	}
	if first.Tree.Hash == second.Tree.Hash {
		return 0, errors.New("tlogiroh: not an equivocation: tree hashes are equal")
	}
	return first.Tree.N, nil
}

// openOperatorCheckpoint verifies that msg is a checkpoint for origin
// carrying the operator's signature and parses it. Unlike Policy.Open it
// ignores witness signatures entirely.
func openOperatorCheckpoint(msg []byte, origin string, operator note.Verifier) (Checkpoint, error) {
	n, err := note.Open(msg, note.VerifierList(operator))
	if err != nil {
		return Checkpoint{}, fmt.Errorf("tlogiroh: open checkpoint: %w", err)
	}
	c, err := ParseCheckpoint([]byte(n.Text))
	if err != nil {
		return Checkpoint{}, err
	}
	if c.Origin != origin {
		return Checkpoint{}, fmt.Errorf("%w: checkpoint names %q, want %q", ErrOriginMismatch, c.Origin, origin)
	}
	return c, nil
}

// An EquivocationError reports a detected split view. It carries the
// verifiable proof; recipients should flood it to peers.
type EquivocationError struct {
	Proof Equivocation
}

func (e *EquivocationError) Error() string {
	return "tlogiroh: equivocation: operator signed two tree heads of the same size"
}
