// SPDX-License-Identifier: Apache-2.0

//go:build !darwin

package main

import (
	"fmt"
	"io"
	"time"
)

// hardenProcess is a no-op off macOS: the csops, PT_DENY_ATTACH, and P_TRACED
// facilities it relies on are Darwin-specific. It reports that no hardening is
// in force so the attestation is honest about it, and refuses -require-maximal.
func hardenProcess(hcfg *hardenedConfig, bundled bool, report io.Writer) (hardeningReport, error) {
	hr := hardeningReport{Bundled: bundled}
	fmt.Fprintln(report, "hardening: unavailable on this platform (macOS only); no anti-debug protections applied")
	if hcfg.RequireMaximal {
		return hr, fmt.Errorf("-require-maximal set but process hardening is only available on macOS")
	}
	return hr, nil
}

// startTraceWatchdog is a no-op off macOS.
func startTraceWatchdog(time.Duration) (stop func()) { return func() {} }
