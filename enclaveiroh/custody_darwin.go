//go:build darwin

package enclaveiroh

import (
	"crypto/rand"
	"errors"
	"fmt"
)

const wrappingKeyLabel = "enclaveiroh endpoint wrapping key"

// obtainSeed returns the ed25519 endpoint seed, wrapping a fresh one on first
// use and unwrapping the stored one thereafter.
//
// The Enclave P-256 wrapping key never leaves the Enclave; only the ECIES
// ciphertext of the seed is persisted, in the Data Protection Keychain. In
// ephemeral mode the wrapping key lives for this process only and nothing is
// persisted, so each run gets a fresh identity — the path that works under an
// ad-hoc signature.
func (ks *KeyStore) obtainSeed() ([]byte, error) {
	wrap, err := ks.wrappingKey()
	if err != nil {
		return nil, err
	}
	defer wrap.Release()

	if ks.Ephemeral {
		// A fresh identity that is never persisted; the seal/open round trip in
		// sealVerified only proves the machine's Enclave can do ECIES.
		seed, err := freshSeed()
		if err != nil {
			return nil, err
		}
		if _, err := sealVerified(wrap, seed); err != nil {
			wipe(seed)
			return nil, err
		}
		return seed, nil
	}

	ciphertext, found, err := loadSecret(ks.service(), ks.account())
	if err != nil {
		return nil, fmt.Errorf("load wrapped seed: %w", err)
	}
	if found {
		seed, err := wrap.Open(ciphertext)
		if err != nil {
			return nil, fmt.Errorf("unwrap seed: %w", err)
		}
		if len(seed) != seedSize {
			wipe(seed)
			return nil, fmt.Errorf("unwrapped seed is %d bytes, want %d", len(seed), seedSize)
		}
		return seed, nil
	}

	seed, err := freshSeed()
	if err != nil {
		return nil, err
	}
	// Verify the round trip before persisting: a Seal-ok but Open-broken Enclave
	// would otherwise commit an identity that is unrecoverable on the next run.
	ciphertext, err = sealVerified(wrap, seed)
	if err != nil {
		wipe(seed)
		return nil, err
	}
	if err := storeSecret(ks.service(), ks.account(), ciphertext); err != nil {
		wipe(seed)
		return nil, fmt.Errorf("persist wrapped seed: %w", err)
	}
	return seed, nil
}

// wrappingKey returns the Enclave P-256 key that wraps the seed, creating it on
// first persistent use and reusing it thereafter. Ephemeral stores get a fresh
// per-process key.
func (ks *KeyStore) wrappingKey() (*enclaveKey, error) {
	tag := []byte(ks.Tag)
	if ks.Ephemeral {
		return generateEnclaveKey(wrappingKeyLabel, tag, false)
	}
	if key, found, err := findEnclaveKey(tag); err != nil {
		return nil, err
	} else if found {
		return key, nil
	}
	key, err := generateEnclaveKey(wrappingKeyLabel, tag, true)
	if errors.Is(err, errMissingEntitlement) {
		return nil, fmt.Errorf("%w: a persistent endpoint identity needs the keychain "+
			"entitlement; run with Ephemeral or bundle with MACGO_TEAM_ID", err)
	}
	return key, err
}

// freshSeed generates a new random ed25519 seed.
func freshSeed() ([]byte, error) {
	seed := make([]byte, seedSize)
	if _, err := rand.Read(seed); err != nil {
		return nil, err
	}
	return seed, nil
}

// sealVerified ECIES-wraps seed to the Enclave key and confirms the Enclave can
// recover it before the ciphertext is trusted. This catches a Seal-ok but
// Open-broken Enclave (or a Mac that cannot perform ECIES) before the identity
// is committed, on both the ephemeral and the persistent path.
func sealVerified(wrap *enclaveKey, seed []byte) ([]byte, error) {
	ciphertext, err := wrap.Seal(seed)
	if err != nil {
		return nil, fmt.Errorf("wrap seed: %w", err)
	}
	got, err := wrap.Open(ciphertext)
	if err != nil {
		return nil, fmt.Errorf("verify wrap: unwrap seed: %w", err)
	}
	defer wipe(got)
	if len(got) != seedSize || !equal(got, seed) {
		return nil, fmt.Errorf("enclave seal/open round trip did not preserve the seed")
	}
	return ciphertext, nil
}

// newSigner builds a Secure Enclave P-256 attestation signer.
func newSigner(tag string, permanent bool) (Signer, error) {
	if permanent {
		key, found, err := findEnclaveKey([]byte(tag))
		if err != nil {
			return nil, err
		}
		if found {
			return key, nil
		}
		key, err = generateEnclaveKey("enclaveiroh attestation key", []byte(tag), true)
		if errors.Is(err, errMissingEntitlement) {
			return nil, fmt.Errorf("%w: a permanent attestation key needs the keychain "+
				"entitlement; use permanent=false or bundle with MACGO_TEAM_ID", err)
		}
		return key, err
	}
	return generateEnclaveKey("enclaveiroh attestation key", []byte(tag), false)
}

// equal reports whether a and b hold the same bytes, in constant time so a seed
// comparison does not leak through timing.
func equal(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var v byte
	for i := range a {
		v |= a[i] ^ b[i]
	}
	return v == 0
}
