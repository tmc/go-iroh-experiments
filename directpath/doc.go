// Package directpath contains helpers for direct iroh path experiments.
//
// The command in cmd/directpath-probe prints local UDP candidates and runs a
// direct-only iroh echo between two hosts. It is intended to isolate direct path
// validation problems without editing github.com/tmc/go-iroh. The command in
// cmd/twobox-directpath is its relay-enabled complement: it proves that a
// relay-coordinated connection upgrades to a validated direct path and
// measures throughput.
package directpath
