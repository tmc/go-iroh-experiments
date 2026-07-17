package enclaveiroh_test

import (
	"fmt"

	"github.com/tmc/go-iroh-experiments/enclaveiroh"
)

// Claim and Policy are pure values, so evaluating a peer's claim runs on any
// platform — only producing one needs the Enclave and the kernel.

func ExamplePolicy_Check() {
	// A peer's claim as the verifier sees it after VerifyClaimSignature and
	// VerifyClaim have passed: a team-signed build with maximal hardening.
	claim := enclaveiroh.Claim{
		Context: enclaveiroh.ClaimContext,
		Role:    enclaveiroh.RoleServe,
		CDHash:  "da874184d2146f78be6a17d8d51a761d2ea29247",
		TeamID:  "EXAMPLETEAM",
		CSFlags: enclaveiroh.CSValid | enclaveiroh.CSRuntime | enclaveiroh.CSHard |
			enclaveiroh.CSKill | enclaveiroh.CSEnforcement | enclaveiroh.CSRequireLV,
	}

	// The zero policy accepts any attested peer (L2); each field opts into a
	// stricter check (toward L3).
	fmt.Println(enclaveiroh.Policy{}.Check(claim))
	fmt.Println(enclaveiroh.Policy{RequireMaximal: true}.Check(claim))
	fmt.Println(enclaveiroh.Policy{AllowedTeamIDs: []string{"OTHERTEAM"}}.Check(claim))
	// Output:
	// <nil>
	// <nil>
	// policy: peer team_id "EXAMPLETEAM" is not allowed
}

func ExampleMaximalFlags() {
	hardened := uint32(enclaveiroh.CSValid | enclaveiroh.CSRuntime | enclaveiroh.CSHard |
		enclaveiroh.CSKill | enclaveiroh.CSEnforcement | enclaveiroh.CSRequireLV)
	fmt.Println(enclaveiroh.MaximalFlags(hardened))
	fmt.Println(enclaveiroh.MaximalFlags(hardened | enclaveiroh.CSGetTaskAllow))
	fmt.Println(enclaveiroh.MaximalFlags(enclaveiroh.CSValid | enclaveiroh.CSKill))
	// Output:
	// true
	// false
	// false
}
