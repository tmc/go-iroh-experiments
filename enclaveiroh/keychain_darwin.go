//go:build darwin

package enclaveiroh

import (
	"errors"
	"fmt"
	"runtime"

	"github.com/tmc/apple/corefoundation"
	"github.com/tmc/apple/security"
)

// OSStatus codes returned by the SecItem functions. The security package
// generates its ErrSec enum with placeholder zero values, so we name the ones
// we branch on here with their documented SecBase.h values.
const (
	errSecSuccess            = 0
	errSecItemNotFound       = -25300
	errSecDuplicateItem      = -25299
	errSecMissingEntitlement = -34018
	errSecParam              = -50
	errSecVerifyFailed       = -67808
)

// errMissingEntitlement is returned when the Data Protection Keychain rejects an
// operation for lack of a keychain-access-groups entitlement backed by a real
// Team ID. It is expected under an ad-hoc signature; see the command's README.
var errMissingEntitlement = errors.New(
	"errSecMissingEntitlement (-34018): the Data Protection Keychain requires a " +
		"keychain-access-groups entitlement signed by a real Apple Team ID; an ad-hoc " +
		"signature is not accepted (use -ephemeral, or bundle with MACGO_TEAM_ID)")

// storeSecret writes secret into the Data Protection Keychain under
// service/account, guarded by a SecAccessControl that requires the device to be
// unlocked. Any prior item with the same service/account is replaced.
//
// On an ad-hoc-signed binary this returns errMissingEntitlement rather than a
// raw status, so callers can report the situation clearly and continue.
func storeSecret(service, account string, secret []byte) error {
	if err := requireConsts(secConsts); err != nil {
		return err
	}
	// Best-effort delete of any prior item so re-runs are idempotent.
	_ = deleteSecret(service, account)

	access, err := newUnlockedAccessControl()
	if err != nil {
		return err
	}
	defer corefoundation.CFRelease(corefoundation.CFTypeRef(access))

	attrs := newDict()
	attrs.setConst(security.KSecClass, security.KSecClassGenericPassword)
	attrs.setBool(security.KSecUseDataProtectionKeychain, true)
	attrs.setStr(security.KSecAttrService, service)
	attrs.setStr(security.KSecAttrAccount, account)
	attrs.setData(security.KSecValueData, secret)
	attrs.setRef(security.KSecAttrAccessControl, uintptr(access))

	status := security.SecItemAdd(attrs.ref(), nil)
	runtime.KeepAlive(attrs)
	return secStatus("SecItemAdd", status)
}

// loadSecret reads a secret previously written by storeSecret. It returns
// found=false when no such item exists.
func loadSecret(service, account string) (secret []byte, found bool, err error) {
	query := newDict()
	query.setConst(security.KSecClass, security.KSecClassGenericPassword)
	query.setBool(security.KSecUseDataProtectionKeychain, true)
	query.setStr(security.KSecAttrService, service)
	query.setStr(security.KSecAttrAccount, account)
	query.setBool(security.KSecReturnData, true)
	query.setConst(security.KSecMatchLimit, security.KSecMatchLimitOne)

	var result corefoundation.CFTypeRef
	status := security.SecItemCopyMatching(query.ref(), &result)
	runtime.KeepAlive(query)

	switch status {
	case errSecItemNotFound:
		return nil, false, nil
	case errSecSuccess:
		data := corefoundation.CFDataRef(result)
		defer corefoundation.CFRelease(result)
		return cfDataBytes(data), true, nil
	default:
		return nil, false, secStatus("SecItemCopyMatching", status)
	}
}

// deleteSecret removes a stored secret. Absence is not an error.
func deleteSecret(service, account string) error {
	query := newDict()
	query.setConst(security.KSecClass, security.KSecClassGenericPassword)
	query.setBool(security.KSecUseDataProtectionKeychain, true)
	query.setStr(security.KSecAttrService, service)
	query.setStr(security.KSecAttrAccount, account)

	status := security.SecItemDelete(query.ref())
	runtime.KeepAlive(query)
	if status == errSecItemNotFound {
		return nil
	}
	return secStatus("SecItemDelete", status)
}

// newUnlockedAccessControl builds a SecAccessControl that gates the item on the
// device being unlocked, without any user-presence prompt. It uses flags=0 so
// the protection class alone governs access.
func newUnlockedAccessControl() (security.SecAccessControlRef, error) {
	protection := corefoundation.CFTypeRef(cfConstString(security.KSecAttrAccessibleWhenUnlockedThisDeviceOnly))

	var cfError corefoundation.CFErrorRef
	access := security.SecAccessControlCreateWithFlags(0, protection, 0, &cfError)
	if err := cfErr(cfError, "SecAccessControlCreateWithFlags"); err != nil {
		return 0, err
	}
	if access == 0 {
		return 0, fmt.Errorf("SecAccessControlCreateWithFlags returned nil")
	}
	return access, nil
}

// secStatus maps a nonzero OSStatus into a Go error, translating the codes
// callers commonly need to branch on.
func secStatus(op string, status int32) error {
	switch status {
	case errSecSuccess:
		return nil
	case errSecMissingEntitlement:
		return errMissingEntitlement
	case errSecDuplicateItem:
		return fmt.Errorf("%s: errSecDuplicateItem (-25299)", op)
	case errSecParam:
		return fmt.Errorf("%s: errSecParam (-50): a query attribute was malformed", op)
	default:
		return fmt.Errorf("%s: OSStatus %d", op, status)
	}
}
