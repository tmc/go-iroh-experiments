//go:build darwin

package enclaveiroh

import (
	"fmt"
	"unsafe"

	"github.com/tmc/apple/corefoundation"
	"github.com/tmc/apple/foundation"
	"github.com/tmc/apple/objc"
	"github.com/tmc/apple/objectivec"
	"github.com/tmc/apple/security"
)

// kUTF8 is CFStringBuiltInEncodings.kCFStringEncodingUTF8.
const kUTF8 = 0x08000100

// cfErr turns a CFErrorRef returned through a Security API into a Go error and
// releases it. It returns nil when the ref is zero (no error).
func cfErr(ref corefoundation.CFErrorRef, action string) error {
	if ref == 0 {
		return nil
	}
	defer corefoundation.CFRelease(corefoundation.CFTypeRef(ref))
	desc := corefoundation.CFErrorCopyDescription(ref)
	if desc == 0 {
		return fmt.Errorf("%s: unknown CoreFoundation error", action)
	}
	defer corefoundation.CFRelease(corefoundation.CFTypeRef(desc))
	return fmt.Errorf("%s: %s", action, cfString(desc))
}

// cfString copies a CFStringRef into a Go string.
func cfString(s corefoundation.CFStringRef) string {
	n := corefoundation.CFStringGetLength(s)
	if n == 0 {
		return ""
	}
	// A BMP code point is at most 3 UTF-8 bytes per UTF-16 unit (4-byte
	// sequences come from surrogate pairs, i.e. two units), so n*4+1 — with +1
	// for the NUL CFStringGetCString writes — is a safe over-allocation.
	buf := make([]byte, n*4+1)
	if !corefoundation.CFStringGetCString(s, &buf[0], len(buf), kUTF8) {
		return ""
	}
	for i, b := range buf {
		if b == 0 {
			return string(buf[:i])
		}
	}
	return string(buf)
}

// dict is a small builder for the CFDictionary attribute maps the Security APIs
// consume. It uses the toll-free-bridged NSMutableDictionary so raw
// CoreFoundation refs and Foundation objects coexist as values.
type dict struct {
	m foundation.NSMutableDictionary
}

func newDict() *dict {
	return &dict{m: foundation.NewMutableDictionaryWithCapacity(8)}
}

func (d *dict) setStr(key, val string)         { d.set(key, foundation.NewStringWithString(val)) }
func (d *dict) setConst(key, val string)       { d.set(key, foundation.NewStringWithString(val)) }
func (d *dict) setBool(key string, val bool)   { d.set(key, foundation.NewNumberWithBool(val)) }
func (d *dict) setData(key string, val []byte) { d.set(key, foundation.NewDataFromBytes(val)) }

func (d *dict) setRef(key string, ref uintptr) {
	d.set(key, objectivec.ObjectFromID(objc.ID(ref)))
}

func (d *dict) setDict(key string, val *dict) { d.set(key, val.m) }

func (d *dict) set(key string, val objectivec.IObject) {
	d.m.SetObjectForKey(val, foundation.NewStringWithString(key))
}

func (d *dict) ref() corefoundation.CFDictionaryRef {
	return corefoundation.CFDictionaryRef(d.m.GetID())
}

// requireConsts fails if the security package could not resolve a constant we
// depend on (an empty string means Dlsym found nothing), turning a confusing
// downstream errSecParam into a precise message.
func requireConsts(named map[string]string) error {
	for name, val := range named {
		if val == "" {
			return fmt.Errorf("security constant %s unavailable (framework symbol missing)", name)
		}
	}
	return nil
}

// secConsts snapshots the Security-framework constants this package relies on,
// so requireConsts and the operations share one source of truth.
var secConsts = map[string]string{
	"kSecClass":                                    security.KSecClass,
	"kSecClassKey":                                 security.KSecClassKey,
	"kSecClassGenericPassword":                     security.KSecClassGenericPassword,
	"kSecAttrKeyType":                              security.KSecAttrKeyType,
	"kSecAttrKeyTypeECSECPrimeRandom":              security.KSecAttrKeyTypeECSECPrimeRandom,
	"kSecAttrKeyClass":                             security.KSecAttrKeyClass,
	"kSecAttrKeyClassPrivate":                      security.KSecAttrKeyClassPrivate,
	"kSecAttrKeySizeInBits":                        security.KSecAttrKeySizeInBits,
	"kSecAttrTokenID":                              security.KSecAttrTokenID,
	"kSecAttrTokenIDSecureEnclave":                 security.KSecAttrTokenIDSecureEnclave,
	"kSecPrivateKeyAttrs":                          security.KSecPrivateKeyAttrs,
	"kSecAttrIsPermanent":                          security.KSecAttrIsPermanent,
	"kSecAttrApplicationTag":                       security.KSecAttrApplicationTag,
	"kSecAttrLabel":                                security.KSecAttrLabel,
	"kSecAttrAccessControl":                        security.KSecAttrAccessControl,
	"kSecAttrAccessibleWhenUnlockedThisDeviceOnly": security.KSecAttrAccessibleWhenUnlockedThisDeviceOnly,
	"kSecUseDataProtectionKeychain":                security.KSecUseDataProtectionKeychain,
	"kSecAttrService":                              security.KSecAttrService,
	"kSecAttrAccount":                              security.KSecAttrAccount,
	"kSecValueData":                                security.KSecValueData,
	"kSecReturnData":                               security.KSecReturnData,
	"kSecReturnRef":                                security.KSecReturnRef,
	"kSecMatchLimit":                               security.KSecMatchLimit,
	"kSecMatchLimitOne":                            security.KSecMatchLimitOne,
}

// cfConstString returns the CFStringRef backing a Security-framework string
// constant. We round-trip through an NSString whose object identity is the
// CFString.
func cfConstString(s string) corefoundation.CFStringRef {
	return corefoundation.CFStringRef(foundation.NewStringWithString(s).GetID())
}

// cfDataFromBytes builds a CFData copy of b. The caller owns the result and must
// CFRelease it.
func cfDataFromBytes(b []byte) corefoundation.CFDataRef {
	if len(b) == 0 {
		return corefoundation.CFDataCreate(0, nil, 0)
	}
	return corefoundation.CFDataCreate(0, b, len(b))
}

// cfDataBytes copies a CFData's contents into a fresh Go slice.
func cfDataBytes(d corefoundation.CFDataRef) []byte {
	n := corefoundation.CFDataGetLength(d)
	if n == 0 {
		return nil
	}
	ptr := corefoundation.CFDataGetBytePtr(d)
	return append([]byte(nil), unsafe.Slice(ptr, n)...)
}
