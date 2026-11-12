package mlsiroh

import (
	"bytes"
	"testing"

	"github.com/tmc/mls"
)

func TestRequestRoundTrip(t *testing.T) {
	tests := []struct {
		name string
		req  request
	}{
		{"fetch key package", request{Version: version, Op: opFetchKeyPackage, Body: []byte{0, 1}}},
		{"deliver welcome", request{Version: version, Op: opDeliverWelcome, Body: bytes.Repeat([]byte{7}, 300)}},
		{"fetch group info", request{Version: version, Op: opFetchGroupInfo, Body: []byte("group")}},
		{"empty body", request{Version: version, Op: opFetchKeyPackage, Body: []byte{}}},
		{"unknown op", request{Version: version, Op: op(200), Body: []byte("x")}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b, err := mls.Marshal(&tt.req)
			if err != nil {
				t.Fatal(err)
			}
			var got request
			if err := mls.Unmarshal(b, &got); err != nil {
				t.Fatal(err)
			}
			if got.Version != tt.req.Version || got.Op != tt.req.Op || !bytes.Equal(got.Body, tt.req.Body) {
				t.Fatalf("round trip = %+v, want %+v", got, tt.req)
			}
		})
	}
}

func TestResponseRoundTrip(t *testing.T) {
	for _, status := range []Status{StatusOK, StatusNotFound, StatusExhausted, StatusMalformed, StatusUnsupported, StatusUnavailable} {
		t.Run(status.String(), func(t *testing.T) {
			want := response{Version: version, Status: status, Body: []byte("body")}
			b, err := mls.Marshal(&want)
			if err != nil {
				t.Fatal(err)
			}
			var got response
			if err := mls.Unmarshal(b, &got); err != nil {
				t.Fatal(err)
			}
			if got.Status != want.Status || !bytes.Equal(got.Body, want.Body) {
				t.Fatalf("round trip = %+v, want %+v", got, want)
			}
		})
	}
}

// TestRequestRejects covers the ways a request can be malformed on the
// wire. Each must be an error, never a panic, and mls.Unmarshal must
// reject trailing bytes so that a body is exact-length by
// construction.
func TestRequestRejects(t *testing.T) {
	good, err := mls.Marshal(&request{Version: version, Op: opFetchKeyPackage, Body: []byte{0, 1}})
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name string
		b    []byte
	}{
		{"empty", nil},
		{"truncated header", good[:2]},
		{"truncated body", good[:len(good)-1]},
		{"trailing bytes", append(append([]byte{}, good...), 0)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var req request
			if err := mls.Unmarshal(tt.b, &req); err == nil {
				t.Fatal("Unmarshal accepted a malformed request")
			}
		})
	}
}

func TestStatusStrings(t *testing.T) {
	if got := Status(200).String(); got != "status(200)" {
		t.Fatalf("Status(200) = %q", got)
	}
	if got := op(200).String(); got != "op(200)" {
		t.Fatalf("op(200) = %q", got)
	}
	err := &Error{Op: opFetchKeyPackage.String(), Status: StatusExhausted}
	if got, want := err.Error(), "fetch_key_package: exhausted"; got != want {
		t.Fatalf("Error = %q, want %q", got, want)
	}
}

func TestMaxResponseSize(t *testing.T) {
	// The caps differ per operation on purpose: a GroupInfo carries
	// the whole ratchet tree and a key package does not.
	if opFetchGroupInfo.maxResponseSize() <= opFetchKeyPackage.maxResponseSize() {
		t.Fatal("group info cap must exceed the key package cap")
	}
	if opDeliverWelcome.maxResponseSize() != 0 {
		t.Fatal("deliver_welcome has no response body")
	}
}
