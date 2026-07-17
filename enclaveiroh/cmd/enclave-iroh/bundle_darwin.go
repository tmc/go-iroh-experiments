// SPDX-License-Identifier: Apache-2.0

//go:build darwin

package main

import (
	"fmt"
	"os"

	"github.com/tmc/macgo"
)

// bundleID, appName, and keychainGroupName identify the generated .app. The
// keychain-access-group is the Team ID plus keychainGroupName.
const (
	bundleID          = "dev.tmc.go-iroh-experiments.enclave-iroh"
	appName           = "enclave-iroh"
	keychainGroupName = "dev.tmc.go-iroh-experiments.enclave-iroh"
)

// maybeBundle re-execs this program from inside a signed .app bundle when
// bundling is requested, so the Data Protection Keychain step is properly
// entitled and the persistent endpoint key can be stored. It returns
// bundled=false when bundling is off, in which case the caller runs under the
// ad-hoc signature (the anti-debug hardening and ephemeral key custody still
// work; the persistent keychain step reports errSecMissingEntitlement).
//
// Bundling is requested by MACGO_TEAM_ID (a 10-char Apple Team ID). macgo's
// Developer ID auto-signing applies the Hardened Runtime (codesign --options
// runtime) — the signature that disables debugger attach — and injects the
// keychain-access-groups entitlement built from the Team ID. That entitlement is
// only honored at launch when authorized by an embedded provisioning profile, so
// set MACGO_PROVISION_PROFILE to a .provisionprofile whose App ID matches
// bundleID.
func maybeBundle() (bundled bool, err error) {
	teamID := os.Getenv("MACGO_TEAM_ID")
	if teamID == "" {
		return false, nil
	}

	group := teamID + "." + keychainGroupName
	cfg := macgo.NewConfig().
		WithAppName(appName).
		WithBundleID(bundleID).
		WithAutoSign(). // Developer ID + Hardened Runtime
		WithCustomString("com.apple.developer.team-identifier", teamID).
		WithCustomArray("keychain-access-groups", group)

	if profile := os.Getenv("MACGO_PROVISION_PROFILE"); profile != "" {
		cfg = cfg.WithProvisioningProfile(profile)
	}
	if os.Getenv("MACGO_DEBUG") != "" {
		cfg = cfg.WithDebug()
	}

	// macgo.Start re-execs into the bundle and blocks there; on the re-exec'd
	// side it returns nil and normal main() flow continues, now entitled.
	if err := macgo.Start(cfg); err != nil {
		return false, fmt.Errorf("macgo bundle/sign: %w", err)
	}
	return true, nil
}
