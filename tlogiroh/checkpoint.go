package tlogiroh

import (
	"bytes"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/mod/sumdb/tlog"
)

// TileHeight is the height of the stored hash tiles, matching the Go
// checksum database tile layout.
const TileHeight = 8

var (
	// ErrNoCheckpoint indicates that a log source holds no published
	// checkpoint yet, or that a client has no stored head.
	ErrNoCheckpoint = errors.New("tlogiroh: no checkpoint")

	// ErrOriginMismatch indicates a checkpoint whose origin line does not
	// match the expected log.
	ErrOriginMismatch = errors.New("tlogiroh: origin mismatch")

	// ErrRollback indicates a signed checkpoint describing a tree smaller
	// than the locally stored head. Clients and witnesses refuse it.
	ErrRollback = errors.New("tlogiroh: tree size smaller than stored head")

	// ErrWitnessThreshold indicates a checkpoint that does not carry the
	// K witness cosignatures required by the policy.
	ErrWitnessThreshold = errors.New("tlogiroh: not enough witness cosignatures")
)

// A Checkpoint is a transparency log tree head: the statement that the log
// named Origin has Tree.N entries and root hash Tree.Hash. Signed
// checkpoints are note messages whose text is the marshaled checkpoint.
type Checkpoint struct {
	Origin string    // log name, first line of the checkpoint
	Tree   tlog.Tree // tree size and root hash
}

// MarshalText formats the checkpoint in the C2SP checkpoint format.
// It returns an error if Origin is empty or contains a newline.
func (c Checkpoint) MarshalText() ([]byte, error) {
	if c.Origin == "" || strings.Contains(c.Origin, "\n") {
		return nil, fmt.Errorf("tlogiroh: invalid checkpoint origin %q", c.Origin)
	}
	if c.Tree.N < 0 {
		return nil, fmt.Errorf("tlogiroh: invalid checkpoint tree size %d", c.Tree.N)
	}
	return fmt.Appendf(nil, "%s\n%d\n%s\n", c.Origin, c.Tree.N, c.Tree.Hash), nil
}

// ParseCheckpoint parses the C2SP checkpoint format: an origin line, a
// decimal tree size line, and a base64 root hash line.
func ParseCheckpoint(text []byte) (Checkpoint, error) {
	s := string(text)
	if !strings.HasSuffix(s, "\n") {
		return Checkpoint{}, errors.New("tlogiroh: malformed checkpoint: missing final newline")
	}
	lines := strings.Split(strings.TrimSuffix(s, "\n"), "\n")
	if len(lines) != 3 {
		return Checkpoint{}, fmt.Errorf("tlogiroh: malformed checkpoint: %d lines, want 3", len(lines))
	}
	if lines[0] == "" {
		return Checkpoint{}, errors.New("tlogiroh: malformed checkpoint: empty origin")
	}
	n, err := strconv.ParseInt(lines[1], 10, 64)
	if err != nil || n < 0 || (lines[1] != "0" && strings.HasPrefix(lines[1], "0")) {
		return Checkpoint{}, fmt.Errorf("tlogiroh: malformed checkpoint: bad tree size %q", lines[1])
	}
	h, err := tlog.ParseHash(lines[2])
	if err != nil {
		return Checkpoint{}, fmt.Errorf("tlogiroh: malformed checkpoint: %w", err)
	}
	return Checkpoint{Origin: lines[0], Tree: tlog.Tree{N: n, Hash: h}}, nil
}

// splitNote splits a signed note message into its text (including the
// trailing newline) and its signature lines.
func splitNote(msg []byte) (text, sigs []byte, err error) {
	i := bytes.Index(msg, []byte("\n\n"))
	if i < 0 {
		return nil, nil, errors.New("tlogiroh: malformed note message")
	}
	return msg[:i+1], msg[i+2:], nil
}

// mergeSignedNotes combines the signature lines of two signed note messages
// carrying the same text, deduplicating identical lines. Witnesses cosign
// independently, so their messages differ only in signatures; merging them
// accumulates cosignatures toward a policy threshold.
func mergeSignedNotes(a, b []byte) ([]byte, error) {
	textA, sigsA, err := splitNote(a)
	if err != nil {
		return nil, err
	}
	textB, sigsB, err := splitNote(b)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(textA, textB) {
		return nil, errors.New("tlogiroh: cannot merge notes with different texts")
	}
	seen := make(map[string]bool)
	merged := append(append([]byte{}, textA...), '\n')
	for line := range strings.Lines(string(sigsA) + string(sigsB)) {
		line = strings.TrimSuffix(line, "\n")
		if line == "" || seen[line] {
			continue
		}
		seen[line] = true
		merged = append(merged, line...)
		merged = append(merged, '\n')
	}
	return merged, nil
}
