//go:build darwin

package enclaveiroh

import "testing"

// TestLocalCodeIdentity checks the csops reads against what any process can
// assert about itself: a 20-byte cdhash, a nonzero flag word, and a signing
// identifier. TeamID is legitimately empty under an ad-hoc test binary.
func TestLocalCodeIdentity(t *testing.T) {
	id, err := LocalCodeIdentity()
	if err != nil {
		t.Fatalf("LocalCodeIdentity() = %v", err)
	}
	if len(id.CDHash) != 20 {
		t.Errorf("CDHash is %d bytes, want 20", len(id.CDHash))
	}
	if id.Flags == 0 {
		t.Error("Flags = 0, want a nonzero CS_OPS_STATUS word")
	}
	if id.Flags&CSValid == 0 {
		t.Error("CS_VALID not set for the running test binary")
	}
	if id.SigningID == "" {
		t.Error("SigningID is empty, want the signing identifier")
	}
}
