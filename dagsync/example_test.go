package dagsync_test

import (
	"fmt"

	"github.com/ipfs/go-cid"
	"github.com/tmc/go-iroh-experiments/dagsync"
)

func ExampleNewSyncRequest() {
	root, err := cid.Parse("bafkreigh2akiscaildcj5uuq5tnp3ixyz4qku4wcmv3ya6u6ntx5ruzoti")
	if err != nil {
		panic(err)
	}
	req := dagsync.NewSyncRequest(dagsync.FullTraversal(root), dagsync.InlineAll())
	fmt.Println(req.Sync.Traversal.Full.Root.Cid == root)
	fmt.Println(req.Sync.Inline.All)
	// Output:
	// true
	// true
}
