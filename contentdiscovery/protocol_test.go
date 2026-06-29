package contentdiscovery

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/tmc/go-iroh/blobs"
	"github.com/tmc/go-iroh/key"
	"github.com/tmc/go-iroh/postcard"
)

func TestPostcardFidelity(t *testing.T) {
	var hostBytes [key.PublicKeySize]byte
	for i := range hostBytes {
		hostBytes[i] = byte(i)
	}
	host, err := key.NewPublicKey(hostBytes)
	if err != nil {
		t.Fatalf("PublicKeyFromBytes: %v", err)
	}
	var hashBytes [32]byte
	for i := range hashBytes {
		hashBytes[i] = byte(0x20 + i)
	}
	var sig [key.SignatureSize]byte
	for i := range sig {
		sig[i] = byte(0x80 + i)
	}

	announce := Announce{
		Host: host.EndpointID(),
		Content: blobs.HashAndFormat{
			Hash:   blobs.HashFromBytes(hashBytes),
			Format: blobs.HashSeq,
		},
		Kind:      AnnounceComplete,
		Timestamp: 300,
	}
	signed := SignedAnnounce{Announce: announce, Signature: sig}
	query := Query{
		Content: announce.Content,
		Flags:   QueryFlags{Complete: true, Verified: false},
	}

	announceBytes, err := postcard.Marshal(announce)
	if err != nil {
		t.Fatalf("Marshal Announce: %v", err)
	}
	wantAnnounce := append([]byte{}, hostBytes[:]...)
	wantAnnounce = append(wantAnnounce, hashBytes[:]...)
	wantAnnounce = append(wantAnnounce, 1)       // BlobFormat HashSeq
	wantAnnounce = append(wantAnnounce, 1)       // AnnounceComplete
	wantAnnounce = append(wantAnnounce, 0xac, 2) // uint64 varint 300
	if !bytes.Equal(announceBytes, wantAnnounce) {
		t.Fatalf("Announce bytes:\ngot  %s\nwant %s", hex.EncodeToString(announceBytes), hex.EncodeToString(wantAnnounce))
	}

	signedBytes, err := postcard.Marshal(signed)
	if err != nil {
		t.Fatalf("Marshal SignedAnnounce: %v", err)
	}
	wantSigned := append(append([]byte{}, wantAnnounce...), sig[:]...)
	if !bytes.Equal(signedBytes, wantSigned) {
		t.Fatalf("SignedAnnounce bytes:\ngot  %s\nwant %s", hex.EncodeToString(signedBytes), hex.EncodeToString(wantSigned))
	}

	queryBytes, err := postcard.Marshal(query)
	if err != nil {
		t.Fatalf("Marshal Query: %v", err)
	}
	wantQuery := append([]byte{}, hashBytes[:]...)
	wantQuery = append(wantQuery, 1, 1, 0) // HashSeq, Complete=true, Verified=false
	if !bytes.Equal(queryBytes, wantQuery) {
		t.Fatalf("Query bytes:\ngot  %s\nwant %s", hex.EncodeToString(queryBytes), hex.EncodeToString(wantQuery))
	}
}

func TestRequestResponsePostcardRoundTrip(t *testing.T) {
	var seed [key.SeedSize]byte
	seed[0] = 1
	sk := key.NewSecretKey(seed)
	announce := Announce{
		Host: sk.Public().EndpointID(),
		Content: blobs.HashAndFormat{
			Hash:   blobs.NewHash([]byte("content")),
			Format: blobs.Raw,
		},
		Kind:      AnnouncePartial,
		Timestamp: 42,
	}
	sig := sk.Sign(mustMarshal(t, announce)).Bytes()
	signed := SignedAnnounce{Announce: announce, Signature: sig}

	req := Request{Kind: RequestAnnounce, Announce: signed}
	reqBytes, err := postcard.Marshal(req)
	if err != nil {
		t.Fatalf("Marshal Request: %v", err)
	}
	if reqBytes[0] != 0 {
		t.Fatalf("Request tag = %d, want 0", reqBytes[0])
	}
	var gotReq Request
	if err := postcard.Unmarshal(reqBytes, &gotReq); err != nil {
		t.Fatalf("Unmarshal Request: %v", err)
	}
	if gotReq.Kind != req.Kind || gotReq.Announce != signed {
		t.Fatalf("Request round trip = %+v, want %+v", gotReq, req)
	}

	resp := Response{Kind: ResponseQueryResponse, QueryResponse: QueryResponse{Hosts: []SignedAnnounce{signed}}}
	respBytes, err := postcard.Marshal(resp)
	if err != nil {
		t.Fatalf("Marshal Response: %v", err)
	}
	if respBytes[0] != 0 {
		t.Fatalf("Response tag = %d, want 0", respBytes[0])
	}
	var gotResp Response
	if err := postcard.Unmarshal(respBytes, &gotResp); err != nil {
		t.Fatalf("Unmarshal Response: %v", err)
	}
	if gotResp.Kind != resp.Kind || len(gotResp.QueryResponse.Hosts) != 1 || gotResp.QueryResponse.Hosts[0] != signed {
		t.Fatalf("Response round trip = %+v, want %+v", gotResp, resp)
	}
}

func mustMarshal(t *testing.T, v any) []byte {
	t.Helper()
	b, err := postcard.Marshal(v)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	return b
}
