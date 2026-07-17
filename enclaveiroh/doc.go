// Package enclaveiroh custodies an iroh endpoint's ed25519 identity in the
// Apple Secure Enclave.
//
// An iroh endpoint is named by its ed25519 secret key; whoever holds that key
// is the endpoint. The Secure Enclave cannot store an ed25519 key directly (it
// holds only NIST P-256 keys), so a [KeyStore] wraps the endpoint seed instead:
// it generates a P-256 key inside the Enclave, ECIES-encrypts the 32-byte
// ed25519 seed to that key's public half, and persists only the ciphertext in
// the Data Protection Keychain. At startup the ciphertext is decrypted by the
// Enclave — the seed is reconstructed for exactly as long as it takes to bind
// the endpoint, then zeroed. The plaintext seed is never written to disk and
// the P-256 private key never leaves the Enclave.
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
// Key custody requires macOS on Apple Silicon or a T2 Mac. On any other
// platform every operation returns [ErrUnsupported]. Persisting a key across
// restarts also requires a keychain-access-groups entitlement backed by a real
// Apple Team ID; under an ad-hoc signature the persistent path reports a
// missing-entitlement error and the ephemeral path (fresh identity per process)
// still works. See the enclave-iroh command for the signing recipe.
package enclaveiroh
