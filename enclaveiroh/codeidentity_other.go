//go:build !darwin

package enclaveiroh

// LocalCodeIdentity is unsupported off macOS: the csops facility it reads is
// Darwin-specific. Verifying a peer's claimed identity works on any platform.
func LocalCodeIdentity() (CodeIdentity, error) {
	return CodeIdentity{}, ErrUnsupported
}
