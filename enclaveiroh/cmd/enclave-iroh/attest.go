// SPDX-License-Identifier: Apache-2.0

package main

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"os"

	"github.com/tmc/go-iroh-experiments/enclaveiroh"
)

// codeSigning describes the code-signing protections the kernel reports for
// this process via csops(CS_OPS_STATUS).
type codeSigning struct {
	Flags        uint32 `json:"flags"`
	Valid        bool   `json:"valid"`              // CS_VALID
	HardenedRT   bool   `json:"hardened_runtime"`   // CS_RUNTIME
	Hard         bool   `json:"hard"`               // CS_HARD
	Kill         bool   `json:"kill"`               // CS_KILL
	Enforcement  bool   `json:"enforcement"`        // CS_ENFORCEMENT
	LibraryValid bool   `json:"library_validation"` // CS_REQUIRE_LV
	GetTaskAllow bool   `json:"get_task_allow"`     // CS_GET_TASK_ALLOW (debuggable)
	Debugged     bool   `json:"debugged"`           // CS_DEBUGGED
}

// String renders the protections as an at-a-glance line.
func (c codeSigning) String() string {
	s := fmt.Sprintf("flags=0x%08x [", c.Flags)
	sep := ""
	add := func(name string, on bool) {
		if on {
			s += sep + name
			sep = " "
		}
	}
	add("valid", c.Valid)
	add("hardened-runtime", c.HardenedRT)
	add("hard", c.Hard)
	add("kill", c.Kill)
	add("enforcement", c.Enforcement)
	add("library-validation", c.LibraryValid)
	add("GET_TASK_ALLOW(!)", c.GetTaskAllow)
	add("DEBUGGED(!)", c.Debugged)
	return s + "]"
}

// Maximal reports whether the process is running with the strongest set of
// protections: a valid Hardened Runtime signature that kills on tampering,
// enforces code signing and library validation, and is not debuggable. An
// ad-hoc go run build reports Valid+Kill but not HardenedRT.
func (c codeSigning) Maximal() bool {
	return c.Valid && c.HardenedRT && c.Kill && c.Enforcement && c.LibraryValid &&
		!c.GetTaskAllow && !c.Debugged
}

// hardeningReport records the hardening state in force during the run; it is
// embedded in the attestation so a verifier sees what the kernel was enforcing,
// not just what the flags requested.
type hardeningReport struct {
	CodeSigning  codeSigning `json:"code_signing"`
	DeniedAttach bool        `json:"denied_attach"`
	Bundled      bool        `json:"bundled"`
	TracePoll    string      `json:"trace_poll,omitempty"`
}

// attestation is the signed record of one endpoint session. Signature covers
// the JSON encoding of the record with the Signature field empty.
type attestation struct {
	Version    int             `json:"version"`
	Tool       string          `json:"tool"`
	Role       string          `json:"role"` // serve or dial
	EndpointID string          `json:"endpoint_id"`
	Peer       string          `json:"peer,omitempty"`
	Ephemeral  bool            `json:"ephemeral_key"`
	Start      string          `json:"start"`
	End        string          `json:"end"`
	Hardening  hardeningReport `json:"hardening"`
	KeyTag     string          `json:"key_tag"`
	PublicKey  string          `json:"public_key"`
	Signature  string          `json:"signature,omitempty"`
}

// payload returns the canonical bytes covered by Signature.
func (a *attestation) payload() ([]byte, error) {
	c := *a
	c.Signature = ""
	return json.Marshal(&c)
}

// signAttestation fills in PublicKey and Signature, self-verifying the
// signature before accepting it.
func signAttestation(att *attestation, signer enclaveiroh.Signer) error {
	pub, err := signer.PublicKey()
	if err != nil {
		return fmt.Errorf("export public key: %w", err)
	}
	att.PublicKey = hex.EncodeToString(pub)

	payload, err := att.payload()
	if err != nil {
		return fmt.Errorf("encode attestation: %w", err)
	}
	sig, err := signer.Sign(payload)
	if err != nil {
		return fmt.Errorf("sign attestation: %w", err)
	}
	ok, err := signer.Verify(payload, sig)
	if err != nil {
		return fmt.Errorf("self-verify attestation: %w", err)
	}
	if !ok {
		return fmt.Errorf("attestation signature failed self-verification")
	}
	att.Signature = hex.EncodeToString(sig)
	return nil
}

// emitAttestation writes the attestation JSON to path, or to report when path is
// empty.
func emitAttestation(att *attestation, path string, report io.Writer) error {
	data, err := json.MarshalIndent(att, "", "  ")
	if err != nil {
		return fmt.Errorf("encode attestation: %w", err)
	}
	data = append(data, '\n')
	if path == "" {
		_, err := report.Write(data)
		return err
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return fmt.Errorf("write attestation: %w", err)
	}
	fmt.Fprintf(report, "attestation written to %s\n", path)
	return nil
}

// verifyAttestationFile checks the signature of an attestation written by
// -attest-out. It uses only the record's embedded public key and the standard
// library, so it runs on any platform, away from the signing machine.
func verifyAttestationFile(path string, out io.Writer) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var att attestation
	if err := json.Unmarshal(data, &att); err != nil {
		return fmt.Errorf("parse attestation: %w", err)
	}
	if att.Signature == "" {
		return fmt.Errorf("attestation carries no signature")
	}
	sig, err := hex.DecodeString(att.Signature)
	if err != nil {
		return fmt.Errorf("decode signature: %w", err)
	}
	pubBytes, err := hex.DecodeString(att.PublicKey)
	if err != nil {
		return fmt.Errorf("decode public key: %w", err)
	}
	pub, err := parseP256PublicKey(pubBytes)
	if err != nil {
		return err
	}
	payload, err := att.payload()
	if err != nil {
		return fmt.Errorf("encode attestation: %w", err)
	}
	digest := sha256.Sum256(payload)
	if !ecdsa.VerifyASN1(pub, digest[:], sig) {
		return fmt.Errorf("signature does not verify against the embedded public key")
	}
	fmt.Fprintf(out, "%s: signature verifies (role %q, endpoint %s, key %s…)\n",
		path, att.Role, att.EndpointID, att.PublicKey[:16])
	return nil
}

// parseP256PublicKey parses an ANSI X9.63 uncompressed P-256 point
// (0x04 || X || Y). The crypto/ecdh round trip validates that the point is on
// the curve before the coordinates are trusted.
func parseP256PublicKey(b []byte) (*ecdsa.PublicKey, error) {
	if _, err := ecdh.P256().NewPublicKey(b); err != nil {
		return nil, fmt.Errorf("invalid P-256 public key: %w", err)
	}
	return &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     new(big.Int).SetBytes(b[1:33]),
		Y:     new(big.Int).SetBytes(b[33:65]),
	}, nil
}
