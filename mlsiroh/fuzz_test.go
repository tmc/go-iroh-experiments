package mlsiroh

import (
	"bytes"
	"fmt"
	"testing"
	"time"

	"github.com/tmc/go-iroh/key"
	"github.com/tmc/mls"
	"github.com/tmc/mls/tlssyntax"
)

// fuzzKey is the endpoint every fuzz seed is bound to.
var fuzzKey = key.NewSecretKey([32]byte{7: 1})

// fuzzSeeds returns a key package and a GroupInfo bound to fuzzKey, each
// in the form a directory serves it.
func fuzzSeeds(f *testing.F) (kp, info []byte) {
	f.Helper()
	c, err := NewClient(fuzzKey, time.Hour)
	if err != nil {
		f.Fatal(err)
	}
	kp, err = mls.Marshal(&mls.Message{Version: mls.Version10, WireFormat: mls.WireFormatKeyPackage, KeyPackage: c.KeyPackage})
	if err != nil {
		f.Fatal(err)
	}
	g, err := c.NewGroup([]byte("group"), nil)
	if err != nil {
		f.Fatal(err)
	}
	gi, err := g.GroupInfo()
	if err != nil {
		f.Fatal(err)
	}
	info, err = mls.Marshal(gi)
	if err != nil {
		f.Fatal(err)
	}
	return kp, info
}

func marshal(f *testing.F, v tlssyntax.Marshaler) []byte {
	f.Helper()
	b, err := mls.Marshal(v)
	if err != nil {
		f.Fatal(err)
	}
	return b
}

// FuzzRequest checks what a directory does with a request: decode it
// and run the operation it names. The operations are called directly
// rather than through dispatch, whose recover would hide a panic.
func FuzzRequest(f *testing.F) {
	_, info := fuzzSeeds(f)
	welcome := marshal(f, &mls.Message{Version: mls.Version10, WireFormat: mls.WireFormatWelcome, Welcome: &mls.Welcome{
		CipherSuite: Suite,
		Secrets:     []mls.EncryptedGroupSecrets{{NewMember: make(mls.HashReference, refSize)}},
	}})
	for _, req := range []*request{
		{Version: version, Op: opFetchKeyPackage, Body: marshal(f, &fetchKeyPackageBody{CipherSuite: Suite})},
		{Version: version, Op: opDeliverWelcome, Body: welcome},
		{Version: version, Op: opFetchGroupInfo, Body: marshal(f, &fetchGroupInfoBody{GroupID: []byte("group")})},
		{Version: version, Op: 9},
	} {
		f.Add(marshal(f, req))
	}
	d := NewDirectory(fuzzKey, nil)
	f.Cleanup(func() { d.Close() })
	var gi mls.Message
	if err := mls.Unmarshal(info, &gi); err != nil {
		f.Fatal(err)
	}
	if err := d.PublishGroupInfo(gi.GroupInfo, nil); err != nil {
		f.Fatal(err)
	}
	for range 4 {
		c, err := NewClient(fuzzKey, time.Hour)
		if err != nil {
			f.Fatal(err)
		}
		if err := d.Add(c.KeyPackage); err != nil {
			f.Fatal(err)
		}
	}
	from := key.NewSecretKey([32]byte{7: 2}).Public().EndpointID()
	f.Fuzz(func(t *testing.T, b []byte) {
		var req request
		if err := mls.Unmarshal(b, &req); err != nil {
			return
		}
		if len(b) > req.Op.maxRequestSize() {
			return
		}
		var status Status
		var body []byte
		switch req.Op {
		case opFetchKeyPackage:
			status, body = d.fetchKeyPackage(from, req.Body)
		case opDeliverWelcome:
			status, body = d.deliverWelcome(from, req.Body)
		case opFetchGroupInfo:
			status, body = d.fetchGroupInfo(from, req.Body)
		default:
			return
		}
		if status != StatusOK && body != nil {
			t.Fatalf("%v answered %v with a body", req.Op, status)
		}
		if len(body) > req.Op.maxResponseSize() {
			t.Fatalf("%v answered %d bytes", req.Op, len(body))
		}
	})
}

// FuzzResponse checks what a client does with a directory's answer: the
// response, and the key package or GroupInfo in its body.
func FuzzResponse(f *testing.F) {
	kp, info := fuzzSeeds(f)
	for _, body := range [][]byte{kp, info, nil, kp[:len(kp)/2]} {
		f.Add(uint8(opFetchKeyPackage), marshal(f, &response{Version: version, Status: StatusOK, Body: body}))
		f.Add(uint8(opFetchGroupInfo), marshal(f, &response{Version: version, Status: StatusOK, Body: body}))
	}
	f.Add(uint8(opDeliverWelcome), marshal(f, &response{Version: version, Status: StatusNotFound}))
	from := fuzzKey.Public().EndpointID()
	now := time.Now()
	f.Fuzz(func(t *testing.T, o uint8, b []byte) {
		body, err := decodeResponse(op(o), b)
		if err != nil {
			return
		}
		switch op(o) {
		case opFetchKeyPackage:
			if kp, err := servedKeyPackage(body, from, now); err == nil {
				if id, err := Verify(kp, now); err != nil || id != from {
					t.Fatalf("servedKeyPackage accepted a key package Verify says is %v, %v", id, err)
				}
			}
		case opFetchGroupInfo:
			_, _ = servedGroupInfo(body, []byte("group"), from)
		}
	})
}

// FuzzParseEntry checks that parseEntry never panics and that an entry
// it accepts is written back as a line it parses the same way.
func FuzzParseEntry(f *testing.F) {
	e := testEntry(1)
	f.Add([]byte(fmt.Sprintf("%x %x %d", []byte(e.Ref), []byte(e.InitKey), e.NotAfter)))
	f.Add([]byte(fmt.Sprintf("%x", []byte(e.Ref))))
	f.Add([]byte(fmt.Sprintf("%x %x -1", []byte(e.Ref), []byte(e.InitKey))))
	f.Add([]byte(""))
	f.Fuzz(func(t *testing.T, line []byte) {
		e, ok := parseEntry(line)
		if !ok {
			return
		}
		if len(e.Ref) != refSize || e.InitKey != nil && len(e.InitKey) != initKeySize {
			t.Fatalf("parseEntry(%q) = %d-byte ref, %d-byte init key", line, len(e.Ref), len(e.InitKey))
		}
		if e.InitKey == nil {
			return
		}
		again, ok := parseEntry([]byte(fmt.Sprintf("%x %x %d", []byte(e.Ref), []byte(e.InitKey), e.NotAfter)))
		if !ok || !bytes.Equal(again.Ref, e.Ref) || !bytes.Equal(again.InitKey, e.InitKey) || again.NotAfter != e.NotAfter {
			t.Fatalf("parseEntry(%q) does not round trip: %+v, %+v", line, e, again)
		}
	})
}

// FuzzVerify checks Verify and VerifyLeaf on key packages as they arrive
// off the wire.
func FuzzVerify(f *testing.F) {
	kp, _ := fuzzSeeds(f)
	f.Add(kp)
	f.Add(kp[:len(kp)-1])
	f.Add(append(bytes.Clone(kp), 0))
	now := time.Now()
	f.Fuzz(func(t *testing.T, b []byte) {
		var msg mls.Message
		if mls.Unmarshal(b, &msg) != nil || msg.KeyPackage == nil {
			return
		}
		id, err := Verify(msg.KeyPackage, now)
		leaf, lerr := VerifyLeaf(&msg.KeyPackage.LeafNode)
		if err == nil && (lerr != nil || leaf != id) {
			t.Fatalf("Verify names %v, VerifyLeaf %v, %v", id, leaf, lerr)
		}
	})
}
