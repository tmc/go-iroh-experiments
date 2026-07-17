package tlogiroh_test

import (
	"context"
	"crypto/rand"
	"fmt"
	"log"

	"github.com/tmc/go-iroh-experiments/tlogiroh"
	"golang.org/x/mod/sumdb/note"
)

// Example appends records to a log, publishes a signed checkpoint, and
// verifies an entry as a client. Witnesses, gossip announcement, and remote
// sources follow the same shapes; see the package documentation.
func Example() {
	skey, vkey, err := note.GenerateKey(rand.Reader, "example.org/log")
	if err != nil {
		log.Fatal(err)
	}
	signer, _ := note.NewSigner(skey)
	verifier, _ := note.NewVerifier(vkey)

	ctx := context.Background()
	op, err := tlogiroh.NewOperator("example.org/log", signer)
	if err != nil {
		log.Fatal(err)
	}
	op.Append(ctx, []byte(`{"artifact":"tool.wasm","verdict":"ok"}`))
	op.Append(ctx, []byte(`{"artifact":"tool2.wasm","verdict":"ok"}`))
	msg, err := op.Publish(ctx)
	if err != nil {
		log.Fatal(err)
	}

	policy, err := tlogiroh.NewPolicy("example.org/log", verifier, nil, 0)
	if err != nil {
		log.Fatal(err)
	}
	client := tlogiroh.NewClient(policy, op.Source())
	head, err := client.Update(ctx, msg)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("tree size:", head.Tree.N)

	entry, err := client.Entry(ctx, 0)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("entry 0: %s\n", entry)
	// Output:
	// tree size: 2
	// entry 0: {"artifact":"tool.wasm","verdict":"ok"}
}
