package enclaveiroh

// Code-signing status flags reported by csops(CS_OPS_STATUS)
// (osfmk/kern/cs_blobs.h). They are pure values, defined off the darwin build
// tag so a verifier on any platform can evaluate a peer's claimed flags.
const (
	CSValid        = 0x00000001 // signature is valid and unmodified
	CSGetTaskAllow = 0x00000004 // task port obtainable (debuggable)
	CSHard         = 0x00000100 // don't load invalid pages
	CSKill         = 0x00000200 // kill the process if it becomes invalid
	CSEnforcement  = 0x00001000 // code-signing enforcement enabled
	CSRequireLV    = 0x00002000 // library validation required
	CSRuntime      = 0x00010000 // Hardened Runtime in effect
	CSDebugged     = 0x10000000 // currently being debugged
)

// CodeIdentity is the kernel-reported code-signing identity of a process:
// what a channel-bound attestation claims about the code holding the
// endpoint. It is obtainable only on macOS; see [LocalCodeIdentity].
type CodeIdentity struct {
	// CDHash is the 20-byte code directory hash — the code identity a
	// verifier pins.
	CDHash []byte

	// TeamID is the signing team, or "" for an ad-hoc or unsigned binary.
	TeamID string

	// SigningID is the signing identifier: a bundle id for a signed .app,
	// "a.out" for an ad-hoc go build. Informative; CDHash is the pin.
	SigningID string

	// Flags is the raw CS_OPS_STATUS word; see the CS* constants.
	Flags uint32
}

// MaximalFlags reports whether flags describe the strongest protection set: a
// valid Hardened Runtime signature that kills on tampering, enforces code
// signing and library validation, and is not debuggable. It is the
// flag-word form of the enclave-iroh command's "maximal hardening" gate.
func MaximalFlags(flags uint32) bool {
	const want = CSValid | CSRuntime | CSHard | CSKill | CSEnforcement | CSRequireLV
	const forbid = CSGetTaskAllow | CSDebugged
	return flags&want == want && flags&forbid == 0
}
