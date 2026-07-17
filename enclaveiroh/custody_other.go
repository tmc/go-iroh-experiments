//go:build !darwin

package enclaveiroh

// obtainSeed is unsupported off macOS.
func (ks *KeyStore) obtainSeed() ([]byte, error) {
	return nil, ErrUnsupported
}

// newSigner is unsupported off macOS.
func newSigner(tag string, permanent bool) (Signer, error) {
	return nil, ErrUnsupported
}
