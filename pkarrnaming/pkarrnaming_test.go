package pkarrnaming

import (
	"strings"
	"testing"

	"github.com/tmc/go-iroh/blobs"
)

func TestParseRecord(t *testing.T) {
	hexHash := strings.Repeat("0a", 32)
	hash, err := blobs.ParseHash(hexHash)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name    string
		in      string
		want    blobs.HashAndFormat
		wantErr bool
	}{
		{name: "hex only", in: hexHash, want: blobs.HashAndFormat{Hash: hash, Format: blobs.Raw}},
		{name: "prefix", in: "blake3:" + hexHash, want: blobs.HashAndFormat{Hash: hash, Format: blobs.Raw}},
		{name: "seq", in: "blake3:" + hexHash + ":seq", want: blobs.HashAndFormat{Hash: hash, Format: blobs.HashSeq}},
		{name: "hashseq", in: hexHash + ":hashseq", want: blobs.HashAndFormat{Hash: hash, Format: blobs.HashSeq}},
		{name: "raw", in: hexHash + ":raw", want: blobs.HashAndFormat{Hash: hash, Format: blobs.Raw}},
		{name: "bad len", in: "abc", wantErr: true},
		{name: "bad hex", in: strings.Repeat("zz", 32), wantErr: true},
		{name: "bad suffix", in: hexHash + ":car", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseRecord(tt.in)
			if tt.wantErr {
				if err == nil {
					t.Fatal("ParseRecord succeeded")
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseRecord: %v", err)
			}
			if got != tt.want {
				t.Fatalf("ParseRecord = %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestRecordStringRoundTrip(t *testing.T) {
	hash := blobs.NewHash([]byte("content"))
	for _, format := range []blobs.BlobFormat{blobs.Raw, blobs.HashSeq} {
		want := blobs.HashAndFormat{Hash: hash, Format: format}
		got, err := ParseRecord(RecordString(want))
		if err != nil {
			t.Fatalf("ParseRecord(%q): %v", RecordString(want), err)
		}
		if got != want {
			t.Fatalf("round trip = %+v, want %+v", got, want)
		}
	}
}
