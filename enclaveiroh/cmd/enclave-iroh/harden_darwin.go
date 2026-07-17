// SPDX-License-Identifier: Apache-2.0

//go:build darwin

package main

import (
	"fmt"
	"io"
	"os"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

// pTraced is the P_TRACED bit of a process's p_flag word (bsd/sys/proc.h). When
// set, the process is being traced by a debugger.
const pTraced = 0x00000800

// csops CS_OPS_STATUS operation and the code-signing status flags it returns
// (osfmk/kern/cs_blobs.h).
const (
	csOpsStatus = 0

	csValid        = 0x00000001 // signature is valid and unmodified
	csGetTaskAllow = 0x00000004 // task port obtainable (debuggable) — want OFF
	csHard         = 0x00000100 // don't load invalid pages
	csKill         = 0x00000200 // kill the process if it becomes invalid
	csEnforcement  = 0x00001000 // code-signing enforcement enabled
	csRequireLV    = 0x00002000 // library validation required
	csRuntime      = 0x00010000 // Hardened Runtime in effect
	csDebugged     = 0x10000000 // currently being debugged — want OFF
)

// hardenProcess applies the anti-debug hardening and returns what the kernel
// reports is in force. It runs before the endpoint key is unwrapped: report the
// code-signing status, optionally insist on a full Hardened Runtime signature,
// refuse to start under a debugger, and ask the kernel to deny every future
// attach.
func hardenProcess(hcfg *hardenedConfig, bundled bool, report io.Writer) (hardeningReport, error) {
	hr := hardeningReport{Bundled: bundled}

	cs, err := codeSigningStatus()
	if err != nil {
		return hr, fmt.Errorf("code-signing status: %w", err)
	}
	hr.CodeSigning = cs
	fmt.Fprintf(report, "hardening: code-signing %s\n", cs)
	if cs.GetTaskAllow {
		fmt.Fprintln(report, "hardening: warning: CS_GET_TASK_ALLOW is set — this process is debuggable")
	}
	if hcfg.RequireMaximal && !cs.Maximal() {
		return hr, fmt.Errorf("maximal hardening not in force (%s); sign with the Hardened Runtime or drop -require-maximal", cs)
	}

	traced, err := isTraced()
	if err != nil {
		return hr, fmt.Errorf("trace check: %w", err)
	}
	if traced {
		return hr, fmt.Errorf("debugger attached; refusing to run")
	}

	if hcfg.DenyAttach {
		if err := denyDebugger(); err != nil {
			return hr, fmt.Errorf("deny debugger: %w", err)
		}
		hr.DeniedAttach = true
		fmt.Fprintln(report, "hardening: PT_DENY_ATTACH applied; debugger attach refused for process lifetime")
	}
	if hcfg.TracePoll > 0 {
		hr.TracePoll = hcfg.TracePoll.String()
	}
	return hr, nil
}

// codeSigningStatus queries the kernel for this process's code-signing flags. It
// is the runtime complement to the static entitlements: it confirms the
// protections a Hardened Runtime signature promises are actually being enforced.
func codeSigningStatus() (codeSigning, error) {
	var flags uint32
	// SYS_CSOPS is flagged deprecated in x/sys (Apple prefers libSystem
	// wrappers), but there is no exported wrapper for csops; a direct read-only
	// status query is the standard approach.
	if _, _, errno := unix.Syscall6(unix.SYS_CSOPS, //nolint:staticcheck
		uintptr(os.Getpid()), uintptr(csOpsStatus),
		uintptr(unsafe.Pointer(&flags)), unsafe.Sizeof(flags), 0, 0); errno != 0 {
		return codeSigning{}, fmt.Errorf("csops CS_OPS_STATUS: %w", errno)
	}
	return codeSigning{
		Flags:        flags,
		Valid:        flags&csValid != 0,
		HardenedRT:   flags&csRuntime != 0,
		Hard:         flags&csHard != 0,
		Kill:         flags&csKill != 0,
		Enforcement:  flags&csEnforcement != 0,
		LibraryValid: flags&csRequireLV != 0,
		GetTaskAllow: flags&csGetTaskAllow != 0,
		Debugged:     flags&csDebugged != 0,
	}, nil
}

// denyDebugger asks the kernel to refuse every future ptrace attach against this
// process for the rest of its lifetime, including from root. It is the macOS
// equivalent of ptrace(PT_DENY_ATTACH). The call errors if a debugger is
// already attached, which is itself a useful signal.
//
// This is a speed bump, not a security boundary: a sufficiently privileged tool
// can still observe the process. It raises the cost of casual attachment and
// pairs with a Hardened Runtime signature that omits get-task-allow.
func denyDebugger() error {
	if err := unix.PtraceDenyAttach(); err != nil {
		return fmt.Errorf("PT_DENY_ATTACH: %w", err)
	}
	return nil
}

// isTraced reports whether a debugger is currently attached, by reading this
// process's kinfo_proc via sysctl and testing the P_TRACED flag. Unlike
// denyDebugger it is non-destructive and can be polled.
func isTraced() (bool, error) {
	kp, err := unix.SysctlKinfoProc("kern.proc.pid", os.Getpid())
	if err != nil {
		return false, fmt.Errorf("sysctl kern.proc.pid: %w", err)
	}
	return kp.Proc.P_flag&pTraced != 0, nil
}

// startTraceWatchdog polls the P_TRACED flag while the endpoint runs and kills
// the process if a debugger appears. PT_DENY_ATTACH already refuses attach; the
// watchdog covers runs where it was skipped or where a tracer won the startup
// race. It returns a stop func for orderly shutdown.
func startTraceWatchdog(interval time.Duration) (stop func()) {
	if interval <= 0 {
		return func() {}
	}
	done := make(chan struct{})
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-done:
				return
			case <-ticker.C:
				if traced, err := isTraced(); err == nil && traced {
					fmt.Fprintln(os.Stderr, "enclave-iroh: debugger attached mid-run; aborting")
					os.Exit(2)
				}
			}
		}
	}()
	return func() { close(done) }
}
