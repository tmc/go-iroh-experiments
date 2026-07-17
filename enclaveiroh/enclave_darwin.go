//go:build darwin

package enclaveiroh

import (
	"fmt"
	"runtime"

	"github.com/tmc/apple/corefoundation"
	"github.com/tmc/apple/foundation"
	"github.com/tmc/apple/security"
)

// eciesAlgorithm is the ECIES variant used to wrap the ed25519 seed. It agrees
// on a shared secret with the Enclave key via cofactor ECDH, derives an AES-GCM
// key with X9.63 KDF over SHA-256, and carries a per-message ephemeral public
// key and IV — so the same seed encrypts to different ciphertext each time.
func eciesAlgorithm() security.SecKeyAlgorithm {
	return security.KSecKeyAlgorithmECIESEncryptionCofactorVariableIVX963SHA256AESGCM
}

// enclaveKey wraps a Secure Enclave-resident P-256 key and its public half. The
// private key material never leaves the Enclave; privRef is only a handle. The
// public key can be exported and used to encrypt to the Enclave.
type enclaveKey struct {
	privRef security.SecKeyRef
	pubRef  security.SecKeyRef
}

// generateEnclaveKey creates a fresh P-256 key inside the Secure Enclave.
//
// The access control combines kSecAccessControlPrivateKeyUsage with the passive
// protection class kSecAttrAccessibleWhenUnlockedThisDeviceOnly, which lets the
// key sign and decrypt headlessly — no biometric or passcode prompt — while
// binding it to this device and refusing use while locked.
//
// With permanent=false repeated runs don't accumulate Enclave keys; with
// permanent=true the private key is stored in the keychain so a later process
// can look it up by its application tag. Persistent storage requires a keychain
// entitlement; under an ad-hoc signature it fails with errSecMissingEntitlement.
func generateEnclaveKey(label string, tag []byte, permanent bool) (*enclaveKey, error) {
	if err := requireConsts(secConsts); err != nil {
		return nil, err
	}

	access, err := newSigningAccessControl()
	if err != nil {
		return nil, err
	}
	defer corefoundation.CFRelease(corefoundation.CFTypeRef(access))

	priv := newDict()
	priv.setBool(security.KSecAttrIsPermanent, permanent)
	priv.setData(security.KSecAttrApplicationTag, tag)
	priv.setRef(security.KSecAttrAccessControl, uintptr(access))

	params := newDict()
	params.setConst(security.KSecAttrKeyType, security.KSecAttrKeyTypeECSECPrimeRandom)
	params.set(security.KSecAttrKeySizeInBits, foundation.NewNumberWithInt(256))
	params.setConst(security.KSecAttrTokenID, security.KSecAttrTokenIDSecureEnclave)
	params.setStr(security.KSecAttrLabel, label)
	params.setDict(security.KSecPrivateKeyAttrs, priv)

	var cfError corefoundation.CFErrorRef
	privRef := security.SecKeyCreateRandomKey(params.ref(), &cfError)
	if err := cfErr(cfError, "SecKeyCreateRandomKey"); err != nil {
		return nil, err
	}
	if privRef == 0 {
		return nil, fmt.Errorf("SecKeyCreateRandomKey returned a nil key (is this an Apple Silicon / T2 Mac with a Secure Enclave?)")
	}

	pubRef := security.SecKeyCopyPublicKey(privRef)
	if pubRef == 0 {
		corefoundation.CFRelease(corefoundation.CFTypeRef(privRef))
		return nil, fmt.Errorf("SecKeyCopyPublicKey returned nil")
	}

	runtime.KeepAlive(params)
	runtime.KeepAlive(priv)
	return &enclaveKey{privRef: privRef, pubRef: pubRef}, nil
}

// findEnclaveKey looks up a permanent Secure Enclave key by its application tag.
// It returns found=false when no such key exists yet.
func findEnclaveKey(tag []byte) (key *enclaveKey, found bool, err error) {
	if err := requireConsts(secConsts); err != nil {
		return nil, false, err
	}
	query := newDict()
	query.setConst(security.KSecClass, security.KSecClassKey)
	query.setData(security.KSecAttrApplicationTag, tag)
	query.setBool(security.KSecReturnRef, true)
	query.setConst(security.KSecMatchLimit, security.KSecMatchLimitOne)
	// Constrain the match to an Enclave-resident private key. Without this a
	// software key planted under the same tag would be adopted as the wrapping
	// key and the seed sealed to a key whose private half is not in the Enclave.
	query.setConst(security.KSecAttrKeyClass, security.KSecAttrKeyClassPrivate)
	query.setConst(security.KSecAttrKeyType, security.KSecAttrKeyTypeECSECPrimeRandom)
	query.setConst(security.KSecAttrTokenID, security.KSecAttrTokenIDSecureEnclave)

	var result corefoundation.CFTypeRef
	status := security.SecItemCopyMatching(query.ref(), &result)
	runtime.KeepAlive(query)
	switch status {
	case errSecItemNotFound:
		return nil, false, nil
	case errSecSuccess:
	default:
		return nil, false, secStatus("SecItemCopyMatching (key)", status)
	}

	privRef := security.SecKeyRef(result)
	pubRef := security.SecKeyCopyPublicKey(privRef)
	if pubRef == 0 {
		corefoundation.CFRelease(result)
		return nil, false, fmt.Errorf("SecKeyCopyPublicKey returned nil for stored key")
	}
	return &enclaveKey{privRef: privRef, pubRef: pubRef}, true, nil
}

// Release frees the CoreFoundation handles. For an ephemeral key this also
// removes the key from the Enclave once the last reference drops.
func (k *enclaveKey) Release() {
	if k == nil {
		return
	}
	if k.pubRef != 0 {
		corefoundation.CFRelease(corefoundation.CFTypeRef(k.pubRef))
		k.pubRef = 0
	}
	if k.privRef != 0 {
		corefoundation.CFRelease(corefoundation.CFTypeRef(k.privRef))
		k.privRef = 0
	}
}

// Seal ECIES-encrypts plaintext to the Enclave key's public half. The result
// can only be opened by the matching private key, which lives in the Enclave.
func (k *enclaveKey) Seal(plaintext []byte) ([]byte, error) {
	data := cfDataFromBytes(plaintext)
	defer corefoundation.CFRelease(corefoundation.CFTypeRef(data))

	var cfError corefoundation.CFErrorRef
	ct := security.SecKeyCreateEncryptedData(k.pubRef, eciesAlgorithm(), data, &cfError)
	if err := cfErr(cfError, "SecKeyCreateEncryptedData"); err != nil {
		return nil, err
	}
	if ct == 0 {
		return nil, fmt.Errorf("SecKeyCreateEncryptedData returned nil")
	}
	defer corefoundation.CFRelease(corefoundation.CFTypeRef(ct))
	return cfDataBytes(ct), nil
}

// Open ECIES-decrypts ciphertext produced by Seal. The key-agreement step runs
// inside the Enclave; the plaintext is returned to the caller.
func (k *enclaveKey) Open(ciphertext []byte) ([]byte, error) {
	data := cfDataFromBytes(ciphertext)
	defer corefoundation.CFRelease(corefoundation.CFTypeRef(data))

	var cfError corefoundation.CFErrorRef
	pt := security.SecKeyCreateDecryptedData(k.privRef, eciesAlgorithm(), data, &cfError)
	if err := cfErr(cfError, "SecKeyCreateDecryptedData"); err != nil {
		return nil, err
	}
	if pt == 0 {
		return nil, fmt.Errorf("SecKeyCreateDecryptedData returned nil")
	}
	defer corefoundation.CFRelease(corefoundation.CFTypeRef(pt))
	return cfDataBytes(pt), nil
}

// PublicKey returns the ANSI X9.63 encoding of the public key
// (0x04 || X || Y for P-256, 65 bytes). This is the representation a verifier
// pins.
func (k *enclaveKey) PublicKey() ([]byte, error) {
	var cfError corefoundation.CFErrorRef
	data := security.SecKeyCopyExternalRepresentation(k.pubRef, &cfError)
	if err := cfErr(cfError, "SecKeyCopyExternalRepresentation"); err != nil {
		return nil, err
	}
	if data == 0 {
		return nil, fmt.Errorf("SecKeyCopyExternalRepresentation returned nil")
	}
	defer corefoundation.CFRelease(corefoundation.CFTypeRef(data))
	return cfDataBytes(data), nil
}

// Sign produces an ECDSA signature (X9.62 DER) over message using the Enclave
// key. The message is hashed with SHA-256 by the algorithm; pass the raw
// message, not a digest.
func (k *enclaveKey) Sign(message []byte) ([]byte, error) {
	if security.KSecKeyAlgorithmECDSASignatureMessageX962SHA256 == 0 {
		return nil, fmt.Errorf("kSecKeyAlgorithmECDSASignatureMessageX962SHA256 unavailable")
	}
	data := cfDataFromBytes(message)
	defer corefoundation.CFRelease(corefoundation.CFTypeRef(data))

	var cfError corefoundation.CFErrorRef
	sig := security.SecKeyCreateSignature(
		k.privRef,
		security.KSecKeyAlgorithmECDSASignatureMessageX962SHA256,
		data,
		&cfError,
	)
	if err := cfErr(cfError, "SecKeyCreateSignature"); err != nil {
		return nil, err
	}
	if sig == 0 {
		return nil, fmt.Errorf("SecKeyCreateSignature returned nil")
	}
	defer corefoundation.CFRelease(corefoundation.CFTypeRef(sig))
	return cfDataBytes(sig), nil
}

// Verify checks an ECDSA signature against message using the public key. A bad
// signature returns (false, nil); a broken call returns an error.
func (k *enclaveKey) Verify(message, signature []byte) (bool, error) {
	msg := cfDataFromBytes(message)
	defer corefoundation.CFRelease(corefoundation.CFTypeRef(msg))
	sig := cfDataFromBytes(signature)
	defer corefoundation.CFRelease(corefoundation.CFTypeRef(sig))

	var cfError corefoundation.CFErrorRef
	ok := security.SecKeyVerifySignature(
		k.pubRef,
		security.KSecKeyAlgorithmECDSASignatureMessageX962SHA256,
		msg,
		sig,
		&cfError,
	)
	if !ok {
		// Distinguish a rejected signature — a normal result, reported as
		// errSecVerifyFailed — from a broken call (bad key ref, unsupported
		// algorithm, errSecParam), which must surface as an error per the
		// interface contract.
		if cfError != 0 {
			code := corefoundation.CFErrorGetCode(cfError)
			if code != errSecVerifyFailed {
				return false, cfErr(cfError, "SecKeyVerifySignature")
			}
			corefoundation.CFRelease(corefoundation.CFTypeRef(cfError))
		}
		return false, nil
	}
	return true, nil
}

// newSigningAccessControl builds a SecAccessControl that permits silent signing
// and decryption on this device while unlocked, with no user-presence prompt.
func newSigningAccessControl() (security.SecAccessControlRef, error) {
	protection := corefoundation.CFTypeRef(cfConstString(security.KSecAttrAccessibleWhenUnlockedThisDeviceOnly))

	var cfError corefoundation.CFErrorRef
	access := security.SecAccessControlCreateWithFlags(
		0, // kCFAllocatorDefault
		protection,
		security.KSecAccessControlPrivateKeyUsage,
		&cfError,
	)
	if err := cfErr(cfError, "SecAccessControlCreateWithFlags"); err != nil {
		return 0, err
	}
	if access == 0 {
		return 0, fmt.Errorf("SecAccessControlCreateWithFlags returned nil")
	}
	return access, nil
}
