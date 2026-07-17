//go:build darwin

package enclaveiroh

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"strings"
	"unsafe"

	"golang.org/x/sys/unix"
)

// csops CS_OPS_* operations used to read this process's code-signing identity
// (osfmk/kern/cs_blobs.h). Verified empirically: CS_OPS_CDHASH demands a
// buffer of exactly cdHashLen bytes (EINVAL otherwise); the blob operations
// return an 8-byte header — uint32 type, uint32 total blob length, big-endian
// — followed by a NUL-terminated string; CS_OPS_TEAMID reports ENOENT when
// the signature carries no team (ad-hoc), which is an answer, not an error.
const (
	csOpsStatus   = 0
	csOpsCDHash   = 5
	csOpsIdentity = 11
	csOpsTeamID   = 14

	cdHashLen = 20
)

// LocalCodeIdentity reads this process's code-signing identity from the
// kernel. Every field is what csops reports at the time of the call.
func LocalCodeIdentity() (CodeIdentity, error) {
	var id CodeIdentity

	var flags uint32
	if err := csops(csOpsStatus, unsafe.Pointer(&flags), unsafe.Sizeof(flags)); err != nil {
		return id, fmt.Errorf("csops CS_OPS_STATUS: %w", err)
	}
	id.Flags = flags

	cd := make([]byte, cdHashLen)
	if err := csops(csOpsCDHash, unsafe.Pointer(&cd[0]), uintptr(len(cd))); err != nil {
		return id, fmt.Errorf("csops CS_OPS_CDHASH: %w", err)
	}
	id.CDHash = cd

	team, err := csopsBlobString(csOpsTeamID)
	if err != nil {
		return id, fmt.Errorf("csops CS_OPS_TEAMID: %w", err)
	}
	id.TeamID = team

	signing, err := csopsBlobString(csOpsIdentity)
	if err != nil {
		return id, fmt.Errorf("csops CS_OPS_IDENTITY: %w", err)
	}
	id.SigningID = signing

	return id, nil
}

// csops wraps the raw syscall for this process. SYS_CSOPS is flagged
// deprecated in x/sys (Apple prefers libSystem wrappers) but has no exported
// wrapper; a read-only status query is the standard approach.
func csops(op uintptr, buf unsafe.Pointer, n uintptr) error {
	if _, _, errno := unix.Syscall6(unix.SYS_CSOPS, //nolint:staticcheck
		uintptr(os.Getpid()), op, uintptr(buf), n, 0, 0); errno != 0 {
		return errno
	}
	return nil
}

// csopsBlobString reads a blob-returning csops operation and extracts its
// string: an 8-byte header (uint32 type, uint32 total blob length, big-endian)
// followed by the NUL-terminated value. ENOENT means the signature has no such
// field and yields "". ERANGE grows the buffer and retries.
func csopsBlobString(op uintptr) (string, error) {
	for size := 128; size <= 4096; size *= 2 {
		buf := make([]byte, size)
		err := csops(op, unsafe.Pointer(&buf[0]), uintptr(len(buf)))
		switch {
		case errors.Is(err, unix.ENOENT):
			return "", nil
		case errors.Is(err, unix.ERANGE):
			continue
		case err != nil:
			return "", err
		}
		total := binary.BigEndian.Uint32(buf[4:8])
		if total < 8 || total > uint32(len(buf)) {
			return "", fmt.Errorf("blob reports length %d outside buffer", total)
		}
		return strings.TrimRight(string(buf[8:total]), "\x00"), nil
	}
	return "", fmt.Errorf("blob larger than 4096 bytes")
}
