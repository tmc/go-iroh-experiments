package x402iroh_test

import (
	"fmt"

	"github.com/tmc/go-iroh-experiments/x402iroh"
	"github.com/tmc/go-iroh/key"
)

func ExampleSignAuthorization() {
	sk := key.NewSecretKey([32]byte{1})
	auth := x402iroh.Authorization{
		From:        sk.Public().EndpointID().String(),
		To:          key.NewSecretKey([32]byte{2}).Public().EndpointID().String(),
		Value:       "10",
		ValidAfter:  "0",
		ValidBefore: "60",
		Nonce:       "0x01",
	}
	payload := x402iroh.ExactPayload{
		Signature:     x402iroh.SignAuthorization(sk, x402iroh.Network, auth),
		Authorization: auth,
	}
	payer, err := x402iroh.VerifyAuthorization(x402iroh.Network, payload)
	fmt.Println(err == nil && payer == sk.Public().EndpointID())
	// Output: true
}
