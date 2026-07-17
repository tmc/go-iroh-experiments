// SPDX-License-Identifier: Apache-2.0

//go:build !darwin

package main

// maybeBundle is a no-op off macOS; there is no .app bundle to re-exec into.
func maybeBundle() (bundled bool, err error) { return false, nil }
