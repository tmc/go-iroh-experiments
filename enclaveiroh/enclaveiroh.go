package enclaveiroh

import (
	"errors"

	"github.com/tmc/go-iroh/key"
)

// ErrUnsupported is returned by every operation on a platform without a Secure
// Enclave. Only macOS on Apple Silicon or a T2 Mac is supported.
var ErrUnsupported = errors.New("enclaveiroh: Secure Enclave key custody requires macOS")

// seedSize is the length of an ed25519 seed, and the plaintext this package
// wraps in the Enclave.
const seedSize = 32

// KeyStore custodies an iroh endpoint's ed25519 seed using a Secure Enclave
// P-256 wrapping key. The zero value is not usable; set at least Tag.
type KeyStore struct {
	// Tag identifies the Enclave wrapping key by its keychain application tag.
	// Reuse the same Tag across runs to keep a stable endpoint identity.
	Tag string

	// Service and Account name the keychain item that holds the wrapped seed
	// ciphertext. Empty values fall back to Tag-derived defaults.
	Service string
	Account string

	// Ephemeral requests a wrapping key that lives only for this process and
	// skips keychain persistence, yielding a fresh endpoint identity on every
	// run. It needs no keychain entitlement, so it is the mode that works under
	// an ad-hoc signature (go run). With Ephemeral false the wrapping key and
	// the ciphertext are persisted, which requires the entitlement.
	Ephemeral bool
}

func (ks *KeyStore) service() string {
	if ks.Service != "" {
		return ks.Service
	}
	return ks.Tag
}

func (ks *KeyStore) account() string {
	if ks.Account != "" {
		return ks.Account
	}
	return "iroh-endpoint-seed"
}

// SecretKey returns the iroh secret key for this store, creating and persisting
// a fresh endpoint identity on first use and unwrapping the stored one
// thereafter. The plaintext seed exists only inside this call.
func (ks *KeyStore) SecretKey() (key.SecretKey, error) {
	if ks.Tag == "" {
		return key.SecretKey{}, errors.New("enclaveiroh: KeyStore.Tag is required")
	}
	seed, err := ks.obtainSeed()
	if err != nil {
		return key.SecretKey{}, err
	}
	defer wipe(seed)
	return key.SecretKeyFromSlice(seed)
}

// Signer is a Secure Enclave-backed P-256 signer whose private key never leaves
// the Enclave. It is used to attest to a run.
type Signer interface {
	// PublicKey returns the ANSI X9.63 encoding of the public key
	// (0x04 || X || Y for P-256, 65 bytes).
	PublicKey() ([]byte, error)
	// Sign returns an ECDSA X9.62 DER signature over SHA-256 of msg.
	Sign(msg []byte) ([]byte, error)
	// Verify reports whether signature matches msg. A bad signature returns
	// (false, nil); a broken call returns an error.
	Verify(msg, signature []byte) (bool, error)
	// Release frees the Enclave key handles.
	Release()
}

// NewSigner returns an Enclave P-256 signer identified by tag. With permanent
// true the key is stored in the keychain and reused across runs, giving a
// stable attestation identity; with permanent false a fresh key signs this run
// only. Persistent keys require the keychain entitlement.
func NewSigner(tag string, permanent bool) (Signer, error) {
	return newSigner(tag, permanent)
}

// wipe zeroes b so a decrypted seed does not linger in memory.
func wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
