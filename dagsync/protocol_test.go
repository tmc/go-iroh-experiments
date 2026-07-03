package dagsync

import (
	"bytes"
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/ipfs/go-cid"
	"github.com/ipld/go-ipld-prime/codec/dagcbor"
	"github.com/ipld/go-ipld-prime/fluent"
	cidlink "github.com/ipld/go-ipld-prime/linking/cid"
	"github.com/ipld/go-ipld-prime/node/basicnode"
	"github.com/multiformats/go-multihash"
	"github.com/tmc/go-iroh/blobs"
	"github.com/tmc/go-iroh/iroh"
	"github.com/tmc/go-iroh/netaddr"
	"github.com/tmc/go-iroh/postcard"
)

func TestResponseHeaderWire(t *testing.T) {
	hash := blobs.NewHash([]byte("hello"))
	b, err := DataHeader(hash).Bytes()
	if err != nil {
		t.Fatalf("Bytes: %v", err)
	}
	if len(b) != 33 {
		t.Fatalf("len = %d, want 33", len(b))
	}
	if b[0] != 1 {
		t.Fatalf("tag = %d, want 1", b[0])
	}
	if !bytes.Equal(b[1:], hash[:]) {
		t.Fatalf("hash bytes mismatch")
	}
	got, err := decodeHeader(b[:])
	if err != nil {
		t.Fatalf("decodeHeader: %v", err)
	}
	if got.Data == nil || *got.Data != hash {
		t.Fatalf("decoded = %#v, want data hash", got)
	}
}

func TestRequestRoundTrip(t *testing.T) {
	c := testCID(t, []byte("hello"))
	want := NewSyncRequest(SequenceTraversal(c), InlineAll())
	b, err := postcard.Marshal(want)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var got Request
	if err := postcard.Unmarshal(b, &got); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if got.Sync == nil || got.Sync.Traversal.Sequence == nil {
		t.Fatalf("decoded request missing sync sequence: %#v", got)
	}
	if !equalCID(got.Sync.Traversal.Sequence.Cids[0].Cid, c) {
		t.Fatalf("cid mismatch")
	}
}

func TestLoopbackSync(t *testing.T) {
	ctx := context.Background()
	data := []byte("hello dagsync")
	c := testCID(t, data)
	source := blobs.BytesMap{}
	sourceTables := NewTables()
	if _, err := sourceTables.ImportBytes(ctx, &source, c, data); err != nil {
		t.Fatalf("ImportBytes source: %v", err)
	}
	req := SyncRequest{Traversal: SequenceTraversal(c), Inline: InlineAll()}
	var wire bytes.Buffer
	if err := WriteSyncResponse(ctx, &wire, req, sourceTables, &source); err != nil {
		t.Fatalf("WriteSyncResponse: %v", err)
	}
	dest := blobs.BytesMap{}
	destTables := NewTables()
	if err := ReadSyncResponse(ctx, &wire, destTables, &dest, req.Traversal); err != nil {
		t.Fatalf("ReadSyncResponse: %v", err)
	}
	hash, ok := destTables.BlobHash(c)
	if !ok {
		t.Fatal("missing imported hash")
	}
	got, ok := dest.Store().GetBlob(hash)
	if !ok {
		t.Fatal("missing imported data")
	}
	if !bytes.Equal(got, data) {
		t.Fatalf("data = %q, want %q", got, data)
	}
}

func TestReadSyncResponseRejectsTamperedBlob(t *testing.T) {
	ctx := context.Background()
	good := []byte("hello dagsync")
	bad := []byte("tampered dagsync")
	c := testCID(t, good)
	wantHash := blobs.NewHash(good)
	gotHash, badBlob, err := blobs.EncodeBlob(bad)
	if err != nil {
		t.Fatalf("EncodeBlob: %v", err)
	}
	if gotHash == wantHash {
		t.Fatal("test data hashes matched")
	}

	var wire bytes.Buffer
	if err := writeHeader(&wire, DataHeader(wantHash)); err != nil {
		t.Fatalf("writeHeader: %v", err)
	}
	if _, err := wire.Write(badBlob); err != nil {
		t.Fatalf("Write: %v", err)
	}
	req := SyncRequest{Traversal: SequenceTraversal(c), Inline: InlineAll()}
	dest := blobs.BytesMap{}
	destTables := NewTables()
	err = ReadSyncResponse(ctx, &wire, destTables, &dest, req.Traversal)
	if err == nil {
		t.Fatal("ReadSyncResponse accepted tampered blob")
	}
	if _, ok := dest.Store().GetBlob(wantHash); ok {
		t.Fatal("stored tampered blob under expected hash")
	}
	if _, ok := destTables.BlobHash(c); ok {
		t.Fatal("recorded cid for rejected blob")
	}
}

func TestFullTraversalFollowsDagCborLinks(t *testing.T) {
	ctx := context.Background()
	childData := []byte("child")
	child := testCID(t, childData)
	rootData, root := dagCBORLinkBlock(t, child)
	source := blobs.BytesMap{}
	sourceTables := NewTables()
	if _, err := sourceTables.ImportBytes(ctx, &source, child, childData); err != nil {
		t.Fatalf("ImportBytes child: %v", err)
	}
	if _, err := sourceTables.ImportBytes(ctx, &source, root, rootData); err != nil {
		t.Fatalf("ImportBytes root: %v", err)
	}
	req := SyncRequest{Traversal: FullTraversal(root), Inline: InlineAll()}
	var wire bytes.Buffer
	if err := WriteSyncResponse(ctx, &wire, req, sourceTables, &source); err != nil {
		t.Fatalf("WriteSyncResponse: %v", err)
	}
	dest := blobs.BytesMap{}
	destTables := NewTables()
	if err := ReadSyncResponse(ctx, &wire, destTables, &dest, req.Traversal); err != nil {
		t.Fatalf("ReadSyncResponse: %v", err)
	}
	for _, c := range []cid.Cid{root, child} {
		hash, ok := destTables.BlobHash(c)
		if !ok {
			t.Fatalf("missing imported hash for %s", c)
		}
		if _, ok := dest.Store().GetBlob(hash); !ok {
			t.Fatalf("missing imported data for %s", c)
		}
	}
}

func dagCBORLinkBlock(t *testing.T, child cid.Cid) ([]byte, cid.Cid) {
	t.Helper()
	node := fluent.MustBuildMap(basicnode.Prototype__Map{}, 1, func(na fluent.MapAssembler) {
		na.AssembleEntry("next").AssignLink(cidlink.Link{Cid: child})
	})
	var buf bytes.Buffer
	if err := dagcbor.Encode(node, &buf); err != nil {
		t.Fatalf("dagcbor.Encode: %v", err)
	}
	data := buf.Bytes()
	mh, err := multihash.Sum(data, multihash.SHA2_256, -1)
	if err != nil {
		t.Fatalf("multihash.Sum: %v", err)
	}
	return data, cid.NewCidV1(cid.DagCBOR, mh)
}

func TestIrohSync(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	data := []byte("hello iroh dagsync")
	c := testCID(t, data)
	source := blobs.BytesMap{}
	sourceTables := NewTables()
	if _, err := sourceTables.ImportBytes(ctx, &source, c, data); err != nil {
		t.Fatalf("ImportBytes source: %v", err)
	}

	server, err := iroh.Bind(ctx, iroh.WithBindAddr(netip.AddrPortFrom(netip.IPv6Loopback(), 0)))
	if err != nil {
		t.Fatalf("bind server: %v", err)
	}
	router, err := iroh.NewRouter(server, map[string]iroh.ProtocolHandler{
		ALPN: &Handler{Tables: sourceTables, Blobs: &source},
	}, nil)
	if err != nil {
		t.Fatalf("new router: %v", err)
	}
	defer router.Shutdown(ctx)

	client, err := iroh.Bind(ctx, iroh.WithBindAddr(netip.AddrPortFrom(netip.IPv6Loopback(), 0)))
	if err != nil {
		t.Fatalf("bind client: %v", err)
	}
	defer client.Shutdown(ctx)

	dest := blobs.BytesMap{}
	destTables := NewTables()
	addr := netaddr.NewEndpointAddr(server.ID()).WithIP(server.LocalAddr())
	req := SyncRequest{Traversal: SequenceTraversal(c), Inline: InlineAll()}
	if err := Sync(ctx, client, addr, destTables, &dest, req); err != nil {
		t.Fatalf("Sync: %v", err)
	}
	hash, ok := destTables.BlobHash(c)
	if !ok {
		t.Fatal("missing imported hash")
	}
	got, ok := dest.Store().GetBlob(hash)
	if !ok {
		t.Fatal("missing imported data")
	}
	if !bytes.Equal(got, data) {
		t.Fatalf("data = %q, want %q", got, data)
	}
}

func testCID(t *testing.T, data []byte) cid.Cid {
	t.Helper()
	mh, err := multihash.Sum(data, multihash.SHA2_256, -1)
	if err != nil {
		t.Fatalf("multihash.Sum: %v", err)
	}
	return cid.NewCidV1(cid.Raw, mh)
}
