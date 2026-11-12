package mlsiroh_test

import (
	"fmt"
	"log"
	"time"

	"github.com/tmc/go-iroh-experiments/mlsiroh"
	"github.com/tmc/go-iroh/key"
	"github.com/tmc/mls"
)

func exampleSession() (*mlsiroh.Session, *mls.Client, key.SecretKey) {
	a, err := key.GenerateSecretKey()
	if err != nil {
		log.Fatal(err)
	}
	b, err := key.GenerateSecretKey()
	if err != nil {
		log.Fatal(err)
	}
	ac, err := mlsiroh.NewClient(a, time.Hour)
	if err != nil {
		log.Fatal(err)
	}
	bc, err := mlsiroh.NewClient(b, time.Hour)
	if err != nil {
		log.Fatal(err)
	}
	g, err := ac.NewGroup([]byte("example incarnation"), nil)
	if err != nil {
		log.Fatal(err)
	}
	s, err := mlsiroh.NewSession(g)
	if err != nil {
		log.Fatal(err)
	}
	return s, bc, b
}

func ExampleNewSession() {
	owner, _, _ := exampleSession()
	_, err := owner.Protect([]byte("hello"))
	fmt.Println(err)
	// Output: <nil>
}

func ExampleSession_Reserve() {
	owner, _, sk := exampleSession()
	a, err := owner.Reserve(sk.Public().EndpointID(), time.Now().Add(time.Minute))
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(a.Info.GroupContext.Epoch)
	_, _, err = owner.Commit(nil)
	fmt.Println(err)
	// Output:
	// 0
	// mlsiroh: epoch reserved for admission
}

func admittedSessions() (*mlsiroh.Session, *mlsiroh.Session, key.SecretKey, mlsiroh.Receipt, *mls.Group, []byte) {
	owner, client, sk := exampleSession()
	a, err := owner.Reserve(sk.Public().EndpointID(), time.Now().Add(time.Minute))
	if err != nil {
		log.Fatal(err)
	}
	var tree mls.RatchetTree
	if ok, err := a.Info.Extensions.Decode(mls.ExtensionTypeRatchetTree, &tree); err != nil || !ok {
		log.Fatal("missing tree")
	}
	provisional, commit, err := client.JoinExternal(a.Info, tree, nil)
	if err != nil {
		log.Fatal(err)
	}
	wire, err := mls.Marshal(commit)
	if err != nil {
		log.Fatal(err)
	}
	receipt, err := owner.Accept(a.Token, a.Endpoint, wire)
	if err != nil {
		log.Fatal(err)
	}
	if !receipt.Matches(provisional, wire) {
		log.Fatal("acceptance mismatch")
	}
	member, err := mlsiroh.NewSession(provisional)
	if err != nil {
		log.Fatal(err)
	}
	return owner, member, sk, receipt, provisional, wire
}

func ExampleSession_Accept() {
	_, _, _, receipt, _, _ := admittedSessions()
	fmt.Println("accepted epoch", receipt.Epoch)
	// Output: accepted epoch 1
}

func ExampleReceipt_Matches() {
	_, _, _, receipt, provisional, wire := admittedSessions()
	fmt.Println(receipt.Matches(provisional, wire))
	// Output: true
}

func ExampleSession_Commit() {
	owner, member, _, _, _, _ := admittedSessions()
	commit, _, err := owner.Commit(nil)
	if err != nil {
		log.Fatal(err)
	}
	content, err := member.Handle(commit)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(content.Content.ContentType == mls.ContentTypeCommit)
	// Output: true
}

func ExampleSession_Protect() {
	owner, member, _, _, _, _ := admittedSessions()
	message, err := member.Protect([]byte("hello"))
	if err != nil {
		log.Fatal(err)
	}
	content, err := owner.Handle(message)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(string(content.Content.ApplicationData))
	// Output: hello
}

func ExampleSession_Handle() {
	ExampleSession_Protect()
	// Output: hello
}

func ExampleSession_Rotate() {
	owner, member, sk, _, _, _ := admittedSessions()
	proposal, err := member.Rotate(sk)
	if err != nil {
		log.Fatal(err)
	}
	if _, err := owner.Handle(proposal); err != nil {
		log.Fatal(err)
	}
	commit, _, err := owner.Commit(nil)
	if err != nil {
		log.Fatal(err)
	}
	if _, err := member.Handle(commit); err != nil {
		log.Fatal(err)
	}
	message, err := member.Protect([]byte("fresh signer"))
	if err != nil {
		log.Fatal(err)
	}
	content, err := owner.Handle(message)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(string(content.Content.ApplicationData))
	// Output: fresh signer
}

func ExampleSession_Receive() {
	owner, member, sk, _, _, _ := admittedSessions()
	message, err := member.Protect([]byte("direct member message"))
	if err != nil {
		log.Fatal(err)
	}
	content, err := owner.Receive(sk.Public().EndpointID(), message, mls.ContentTypeApplication)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(string(content.Content.ApplicationData))
	// Output: direct member message
}
