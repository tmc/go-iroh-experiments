package contentdiscovery_test

import (
	"fmt"

	"github.com/tmc/go-iroh-experiments/contentdiscovery"
	"github.com/tmc/go-iroh/blobs"
	"github.com/tmc/go-iroh/key"
)

func ExampleSignAnnounce() {
	sk := key.NewSecretKey([32]byte{1})
	announce := contentdiscovery.Announce{
		Host:      sk.Public().EndpointID(),
		Content:   blobs.RawHash(blobs.NewHash([]byte("example"))),
		Kind:      contentdiscovery.AnnounceComplete,
		Timestamp: 1,
	}
	signed, err := contentdiscovery.SignAnnounce(sk, announce)
	if err != nil {
		panic(err)
	}
	fmt.Println(contentdiscovery.VerifySignedAnnounce(signed))
	// Output: true
}
