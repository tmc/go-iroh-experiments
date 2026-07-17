# enclaveiroh

Custody an iroh endpoint's identity in the Apple Secure Enclave, and run it
inside a hardened process.

An iroh endpoint is named by its ed25519 secret key; whoever holds that key is
the endpoint. This package keeps that key *off disk*: the Secure Enclave holds a
P-256 key that never leaves the hardware, the 32-byte ed25519 seed is
ECIES-encrypted to it, and only the ciphertext is persisted in the Data
Protection Keychain. At startup the seed is decrypted by the Enclave and bound
into the endpoint.

Custody protects the identity **at rest**, not in live memory: an ed25519 signer
must retain the private key to sign every TLS handshake, so once the endpoint is
bound the seed lives in the process for the whole session. Guarding it there is
the job of the process hardening (below), which runs for the entire run.

The `enclave-iroh` command wraps that key custody in the same anti-debug harness
as the [tmc/apple secure-enclave demo](https://github.com/tmc/mlx-go-lm): it
reads the kernel's code-signing status, refuses to start under a debugger,
applies `PT_DENY_ATTACH`, and polls `P_TRACED` while the endpoint runs. Each
session is recorded in a Secure-Enclave-signed attestation.

## Library

```go
ks := &enclaveiroh.KeyStore{Tag: "dev.example.node"}
sk, err := ks.SecretKey() // creates+wraps on first use, unwraps thereafter
if err != nil {
	log.Fatal(err)
}
ep, err := iroh.Bind(ctx, iroh.WithSecretKey(sk), iroh.WithALPNs("example/1"))
```

`Signer` exposes the same Enclave P-256 primitive for signing an attestation.

## Command

```
enclave-iroh serve [-tag <id>] [-ephemeral] [-bind <addr>] [-attest-out <f>]
enclave-iroh dial  -server <ticket> [-tag <id>] [-ephemeral] [msg...]
enclave-iroh verify-attestation <file>
```

`serve` binds an endpoint, prints its ticket, and echoes newline-delimited lines
back uppercased. `dial` connects to a ticket, sends each message, and prints the
replies. `verify-attestation` checks a signed session record using only the
standard library, so it runs on any platform.

A loopback demo, both sides in ephemeral mode:

```
$ enclave-iroh serve -ephemeral &
ticket: endpointa...
hardening: code-signing flags=0x22020201 [valid kill]
hardening: PT_DENY_ATTACH applied; debugger attach refused for process lifetime
custody: endpoint key 993dfad7… (ephemeral, enclave-wrapped in memory)

$ enclave-iroh dial -ephemeral -server endpointa... "hello enclave"
hello enclave -> HELLO ENCLAVE

$ enclave-iroh verify-attestation dial-att.json
dial-att.json: signature verifies (role "dial", endpoint 8cc7b8ce…, key 04bb9a0a…)
```

## Persistent vs ephemeral identity

A **persistent** identity (the default) reuses one endpoint key across restarts.
The wrapping key and the wrapped-seed ciphertext both live in the Data
Protection Keychain, which requires a `keychain-access-groups` entitlement backed
by a real Apple Team ID. Set `MACGO_TEAM_ID` (and `MACGO_PROVISION_PROFILE`) so
the process re-execs inside a Developer-ID-signed `.app` with the Hardened
Runtime before it touches the keychain:

```
MACGO_TEAM_ID=XXXXXXXXXX \
MACGO_PROVISION_PROFILE=enclave-iroh.provisionprofile \
enclave-iroh serve -tag dev.example.node
```

An **ephemeral** identity (`-ephemeral`) uses a fresh in-memory Enclave wrapping
key and skips keychain persistence, so it needs no entitlement and runs under an
ad-hoc `go run` signature. Each run gets a new endpoint identity. This is the
mode the loopback demo above uses.

## Threat model

The Enclave protects the endpoint key *at rest*: an attacker who reads the disk
or the keychain database gets only ciphertext they cannot decrypt without the
Enclave. In memory the seed is present for the whole session (iroh must hold the
ed25519 private key to sign every handshake), so `PT_DENY_ATTACH` and the trace
watchdog run for the entire run to raise the cost of attaching a debugger to
read it. Neither is a boundary against a sufficiently privileged attacker (a
kernel extension, or a debugger attached before hardening runs); they are speed
bumps that pair with a Hardened Runtime signature.

See [THREAT-MODEL.md](THREAT-MODEL.md) for the full model — assets, adversary
tiers, and why proving the *peer* runs the published code needs an external root
of trust that macOS does not provide.

## Requirements

Key custody and hardening require macOS on Apple Silicon or a T2 Mac. On any
other platform the library returns `ErrUnsupported`; `verify-attestation` works
everywhere.
