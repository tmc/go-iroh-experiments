// Package enclaveiroh custodies an iroh endpoint's ed25519 identity in the
// Apple Secure Enclave.
//
// An iroh endpoint is named by its ed25519 secret key; whoever holds that key
// is the endpoint. The Secure Enclave cannot store an ed25519 key directly (it
// holds only NIST P-256 keys), so a [KeyStore] wraps the endpoint seed instead:
// it generates a P-256 key inside the Enclave, ECIES-encrypts the 32-byte
// ed25519 seed to that key's public half, and persists only the ciphertext in
// the Data Protection Keychain. At startup the ciphertext is decrypted by the
// Enclave and the seed is bound into the endpoint. The KeyStore's own copy of
// the seed is then zeroed, but the seed is not gone from the process: an
// ed25519 signer must keep the private key to sign every TLS handshake, so it
// lives in [iroh.Endpoint] for the endpoint's whole lifetime. What custody buys
// is protection at rest — the plaintext seed is never written to disk, only its
// ciphertext, and the P-256 private key never leaves the Enclave. Protecting the
// seed while it is live in memory is the job of the process hardening in the
// enclave-iroh command, which runs for the whole session, not just at bind.
//
//	ks := &enclaveiroh.KeyStore{Tag: "dev.example.node"}
//	sk, err := ks.SecretKey()
//	if err != nil {
//		log.Fatal(err)
//	}
//	ep, err := iroh.Bind(ctx, iroh.WithSecretKey(sk), iroh.WithALPNs("example/1"))
//
// [Signer] exposes the same Enclave-resident P-256 primitive as a signer, for
// attesting to a run.
//
// The package also implements the channel-bound attestation handshake of
// ATTEST.md: each side of an iroh connection proves, under an Enclave-resident
// key, what code it runs — bound to exactly this connection and session.
// [Handshake] runs on the first bidirectional stream of a connection, before
// any application stream. An attesting side signs a [Claim] carrying its
// [CodeIdentity] (cdhash, Team ID, and code-signing flags, read from the
// kernel) together with its role, both endpoint IDs, both session nonces, and
// the connection's ALPN, so a claim cannot be replayed, transplanted onto
// another channel, or reflected. [Policy] is the verifier's acceptance
// criteria over the peer's claim, from any attested peer (the zero value) to
// pinned teams, cdhashes, and keys:
//
//	att, err := enclaveiroh.Handshake(ctx, conn, enclaveiroh.HandshakeConfig{
//		SelfID:   ep.ID(),
//		Mode:     enclaveiroh.ModeMutual,
//		Signer:   signer,
//		Identity: identity,
//		Policy:   enclaveiroh.Policy{RequireMaximal: true},
//	})
//
// Producing a claim requires the Enclave and the kernel's code-signing state,
// but verifying one does not: [VerifyClaimSignature], [VerifyClaim], and
// [Policy.Check] use only the standard library, so a non-darwin peer can
// verify claims it cannot produce ([ModeVerify]). Every claim remains
// self-reported by the peer's process — the handshake narrows who can lie, it
// does not remove lying; see THREAT-MODEL.md.
//
// Key custody requires macOS on Apple Silicon or a T2 Mac. On any other
// platform every operation returns [ErrUnsupported]. Persisting a key across
// restarts also requires a keychain-access-groups entitlement backed by a real
// Apple Team ID; under an ad-hoc signature the persistent path reports a
// missing-entitlement error and the ephemeral path (fresh identity per process)
// still works. See the enclave-iroh command for the signing recipe.
package enclaveiroh
