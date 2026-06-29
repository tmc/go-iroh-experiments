package pkarrnaming

import (
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/tmc/go-iroh/blobs"
)

// Record is a named iroh content root.
type Record = blobs.HashAndFormat

// RecordString formats r as a pkarrnaming TXT value.
func RecordString(r blobs.HashAndFormat) string {
	s := "blake3:" + r.Hash.String()
	if r.Format == blobs.HashSeq {
		return s + ":seq"
	}
	return s
}

// ParseRecord parses a pkarrnaming TXT value.
func ParseRecord(s string) (blobs.HashAndFormat, error) {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "blake3:")

	hexPart := s
	suffix := ""
	if i := strings.IndexByte(s, ':'); i >= 0 {
		hexPart, suffix = s[:i], s[i+1:]
	}
	if len(hexPart) != 64 {
		return blobs.HashAndFormat{}, errors.New("pkarrnaming: hash must be 64 hex chars")
	}
	raw, err := hex.DecodeString(hexPart)
	if err != nil {
		return blobs.HashAndFormat{}, fmt.Errorf("pkarrnaming: parse hash: %w", err)
	}
	var h [32]byte
	copy(h[:], raw)
	format := blobs.Raw
	switch suffix {
	case "", "raw":
	case "seq", "hashseq":
		format = blobs.HashSeq
	default:
		return blobs.HashAndFormat{}, fmt.Errorf("pkarrnaming: unknown format %q", suffix)
	}
	return blobs.HashAndFormat{Hash: blobs.HashFromBytes(h), Format: format}, nil
}
