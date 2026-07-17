# enclaveiroh threat model

## Purpose and question

This document models the security of running a go-iroh endpoint whose identity
is custodied in the Apple Secure Enclave (`enclaveiroh`), and asks one concrete
question:

> Can two peers on a go-iroh network be confident that messages are flowing
> between the *exact published Go code*, and not around it?

The honest answer is a ladder, not a yes/no. This document defines the assets,
the trust boundaries, the adversaries, and then walks each threat to the
mitigation that is in place, the mitigation that is proposed, and the residual
risk that no amount of local hardening removes. The load-bearing conclusion is
stated up front so the rest can be read against it:

> **iroh already proves message flow between two cryptographic *identities*.
> The Secure Enclave makes that identity non-exfiltratable and stable. Neither
> proves *which code* holds the identity. Proving the peer runs a specific
> binary requires a root of trust the peer cannot forge — and stock macOS does
> not provide one for native binaries. Everything below is about how close we
> get without it, and exactly where the cliff is.**

## System model

```
   Published Go build ──(reproducible, -trimpath)──► known cdhash / Team ID
            │
            ▼
   ┌─────────────────────── machine (peer) ───────────────────────┐
   │  ┌── process (enclave-iroh) ────────────────────────────┐    │
   │  │  ed25519 private key: in RAM for the whole session   │    │
   │  │  iroh endpoint  ◄── WithSecretKey(seed)              │    │
   │  └───────────▲───────────────────────────▲──────────────┘    │
   │              │ SecKeyCreateDecryptedData  │ csops(status)     │
   │   ┌──────────┴─────────┐        ┌─────────┴──────────┐        │
   │   │  Secure Enclave    │        │   XNU kernel       │        │
   │   │  P-256 wrapping key│        │  code-sign flags,  │        │
   │   │  P-256 attest key  │        │  P_TRACED, AMFI    │        │
   │   └────────────────────┘        └────────────────────┘        │
   │   ┌────────────────────────────────────────────────┐         │
   │   │  Data Protection Keychain: ECIES(seed) ciphertext│        │
   │   │  gated by keychain-access-groups (Team ID)       │        │
   │   └────────────────────────────────────────────────┘         │
   └───────────────────────────────┬──────────────────────────────┘
                                    │  iroh QUIC/TLS (authenticated,
                                    │  encrypted with the ed25519 key)
   ┌────────────────────────────────▼─────────────────────────────┐
   │                          peer / verifier                      │
   └───────────────────────────────────────────────────────────────┘
```

Components:

- **Published build** — the Go binary under review. With `-trimpath`, a pinned
  toolchain, and Developer-ID + notarization, it has a deterministic code
  identity (the Mach-O *cdhash*) and a signing *Team ID*.
- **Process** — the running `enclave-iroh`. `SecKeyCreateDecryptedData` recovers
  the seed, `iroh.Bind` copies it into the endpoint, and the KeyStore's own copy
  is zeroed — but iroh must retain the ed25519 private key to sign every TLS
  handshake, so the key material stays in process memory (in `iroh.Endpoint`, and
  in every `key.SecretKey` value copied along the way) for the endpoint's whole
  lifetime. Custody is an at-rest protection, not an in-memory one.
- **Secure Enclave** — holds two P-256 keys whose private halves never leave
  the hardware: the *wrapping key* (unwraps the endpoint seed via ECIES) and the
  *attestation key* (signs session records).
- **XNU / AMFI** — reports code-signing status via `csops`, enforces the
  Hardened Runtime and library validation, and sets `P_TRACED` under a debugger.
- **Data Protection Keychain** — stores only the ECIES ciphertext of the seed,
  optionally gated by a `keychain-access-groups` entitlement tied to the Team ID.
- **iroh transport** — QUIC/TLS authenticated and encrypted with the endpoint's
  ed25519 key.

## Assets

| ID | Asset | Why it matters |
|----|-------|----------------|
| AS1 | ed25519 endpoint seed | Whoever holds it *is* the endpoint. Theft ⇒ silent impersonation on the whole network. |
| AS2 | Message confidentiality & integrity | The payload flowing over iroh streams. |
| AS3 | Peer authenticity (identity) | "The other end is endpoint X." |
| AS4 | Peer code integrity | "Endpoint X is the published binary, unmodified." — the hard asset. |
| AS5 | Attestation trust chain | The signed record a verifier relies on to believe AS4. |
| AS6 | Wrapped-seed ciphertext at rest | Stored in the keychain; only useful with the Enclave. |

## Trust assumptions

The model takes these as given. If any is false, the guarantees above it
collapse; they are listed so the failure is explicit, not hidden.

- **TA1** — The Apple Silicon / T2 Secure Enclave is sound: private keys are not
  extractable, and it performs ECDH/ECDSA honestly.
- **TA2** — On a machine with an *uncompromised kernel*, `csops` reports the
  running image's true code-signing status and cdhash.
- **TA3** — ed25519, P-256 ECDSA, and ECIES (cofactor X9.63 / AES-GCM) are
  cryptographically sound, as is iroh's QUIC/TLS.
- **TA4** — The published build is reproducible, so a verifier can compute the
  cdhash it intends to pin from source + toolchain.
- **TA5** — The verifier itself, and its list of pinned cdhashes / trusted Team
  IDs, are not attacker-controlled.

## Adversary model

Capability tiers, from weakest to strongest. Each threat below is tagged with
the weakest adversary that can mount it.

| ID | Adversary | Can | Cannot (per trust assumptions) |
|----|-----------|-----|--------------------------------|
| A0 | Passive network observer | Read/record ciphertext on the wire | Decrypt or forge iroh traffic (TA3) |
| A1 | Active network attacker | Inject, drop, replay, MITM the network | Impersonate an endpoint key it doesn't hold |
| A2 | **Malicious peer operator** | Fully control *their own* endpoint machine: run any code, patch binaries, use the OS's own Enclave APIs | Extract a *different* peer's Enclave key |
| A3 | Local unprivileged code (victim's box) | Run as the same/lower-priv user, probe files/keychain | Read another app's Data-Protection item; attach to a PT_DENY_ATTACH process without escalation |
| A4 | Local privileged / kernel (victim's box) | root, kexts, DTrace, patch memory | Break TA1/TA2 only by also compromising the kernel (then TA2 is void) |
| A5 | Physical attacker | Cold-boot, bus probing, coercion | Extract from the Enclave (TA1) |
| A6 | Supply-chain | Compromise the build, a dependency, or the toolchain | — (defeats the *definition* of "published code"; see T10) |

A2 is the adversary that matters most for the headline question. When you ask
"is the peer running published code," the peer is, by definition, someone you do
not control and may be adversarial. No client-side hardening constrains A2 — it
only constrains adversaries acting *against* a peer (A1, A3–A5).

## Threats

Each entry: the threat, the weakest adversary, the impact on an asset, the
mitigation in place today (▣) or proposed (▢) or none (□), and the residual risk.

### T1 — Endpoint key theft at rest
- **Adversary:** A3 (read the keychain DB / disk image), A5 (steal the disk)
- **Impact:** AS1 → full impersonation (AS3)
- **Mitigation ▣:** the seed is never stored; only `ECIES(seed)` to the Enclave
  wrapping key is persisted, inside the Data Protection Keychain
  (`kSecAttrAccessibleWhenUnlockedThisDeviceOnly`). Decryption requires the
  Enclave, which is device-bound.
- **Residual:** none for the ciphertext alone. An attacker with the disk but not
  the live, unlocked Enclave gets nothing usable.

### T2 — Key extraction from live process memory
- **Adversary:** A4 (root/kernel reads RAM), A5 (cold-boot)
- **Impact:** AS1 for the whole session
- **Mitigation ▣:** `PT_DENY_ATTACH` and the `P_TRACED` watchdog run for the
  entire run, and Hardened Runtime + library validation block code injection
  under a proper signature. The exposure is **not** a short bind window: iroh
  retains the ed25519 private key to sign every handshake, so the key is in
  memory for the endpoint's lifetime (see the Process component). `wipe()` clears
  only the KeyStore's transient copy, not iroh's. This is why the watchdog polls
  continuously rather than only guarding startup.
- **Residual:** a privileged local attacker (A4) or physical attacker (A5) can
  read process memory at any point in the session. These are speed bumps, not a
  boundary. There is no "shrink the window" lever — the window is the run — so
  the honest guarantee is: at-rest custody (T1) keeps the key encrypted when the
  process is not running, and whole-run hardening raises the cost of reading it
  while it is.

### T3 — Impersonation of the endpoint elsewhere
- **Adversary:** A3–A5 after succeeding at T2
- **Impact:** AS3 network-wide
- **Mitigation ▣:** because the key is non-exfiltratable at rest (T1), the only
  path is the live-memory window (T2). Persistent identity also requires the
  keychain entitlement (T8), so a stolen ciphertext cannot be rehydrated by an
  arbitrary binary.
- **Residual:** inherits T2's residual.

### T4 — Network eavesdrop / MITM / replay of messages
- **Adversary:** A0, A1
- **Impact:** AS2, AS3
- **Mitigation ▣:** iroh's QUIC/TLS authenticates the channel with the endpoint
  ed25519 key and encrypts it. An attacker without the key cannot read, forge,
  or MITM without detection.
- **Residual:** none beyond TA3. This asset is *fully* covered — and it is the
  part people often conflate with AS4, which is *not* covered here.

### T5 — Malicious peer runs modified code under a genuine identity
- **Adversary:** A2
- **Impact:** **AS4** — the central gap
- **Mitigation □ / ▢:** identity (AS3) says nothing about code. A peer can hold a
  perfectly valid endpoint key (even an Enclave-custodied one) inside a patched,
  reimplemented, or instrumented binary and speak the protocol correctly. The
  proposed attestation (T6) lets the peer *self-report* its cdhash, but a peer
  that controls its machine can make its process report or sign whatever it
  wants (see T7's self-attestation gap).
- **Residual:** **unmitigable within these primitives.** Closing T5 against A2
  requires an external root of trust (see "What remains open").

### T6 — Forged or replayed attestation
- **Adversary:** A1 (replay a captured attestation), A2 (mint a plausible one)
- **Impact:** AS5
- **Mitigation ▢ (proposed):** a per-connection, channel-bound handshake on a
  dedicated ALPN: the Enclave attestation key signs `H(nonce ‖ endpoint_pubkey ‖
  cdhash ‖ team_id ‖ code_sign_flags)`, where `nonce` is fresh per connection and
  `endpoint_pubkey` is the live transport key. This binds the attestation to
  *this* session (defeats replay, A1) and to *this* transport identity (defeats
  lifting an attestation onto a different channel).
- **Residual:** replay and cross-channel transplant are closed. A2 forging a
  *truthful-looking but false* attestation is **not** — that is T7.

### T7 — Self-attestation trust gap
- **Adversary:** A2
- **Impact:** AS4, AS5
- **Mitigation □:** the attestation is signed by a key the peer's own process
  controls. The Secure Enclave protects key *secrecy*, not *which code invokes
  it*: a modified process that can reach or mint an Enclave key can sign an
  attestation claiming the published cdhash while running anything. `csops` reads
  the *true* cdhash of the *reader* (TA2), so the value is honest about the
  process that reads it — but nothing forces the *signer* to embed its own true
  cdhash rather than a chosen constant.
- **Residual:** this is the irreducible limit on macOS. It is why AS4 cannot be
  proven against A2 without an external attestor.

### T8 — Unauthorized binary uses the persistent key
- **Adversary:** A3 (another app on the box), A2 (a different binary they wrote)
- **Impact:** AS1, AS4
- **Mitigation ▣ (bundled path):** the persistent wrapping key and the ciphertext
  live under a `keychain-access-groups` entitlement bound to the Team ID and
  authorized by an embedded provisioning profile. Only a binary signed by that
  team, carrying that entitlement, can reach them. An unsigned or foreign-signed
  binary gets `errSecMissingEntitlement`.
- **Residual:** this narrows "any code" to "code signed by *this team* with *this
  entitlement*" — a real, enforceable gate, but not down to a single cdhash. A
  second binary from the same team could still access the key. It is the
  strongest native-macOS lever toward AS4.
- **Related:** the wrapping-key lookup (`findEnclaveKey`) constrains the match to
  `kSecAttrTokenIDSecureEnclave` + private key class, so a *software* key planted
  under the same application tag is not silently adopted (which would seal the
  seed to a non-Enclave key). T8 gates *access* to the stored items; this check
  ensures the key that comes back is actually Enclave-resident.

### T9 — Downgrade to the unentitled / ad-hoc path
- **Adversary:** A2, A3
- **Impact:** bypasses T8 by using `-ephemeral`, which needs no entitlement
- **Mitigation ▢ (proposed):** the verifier rejects attestations whose embedded
  code-signing state is not `Maximal()` (Hardened Runtime, kill, enforcement,
  library validation, not debuggable, not `get_task_allow`) and that are not
  `bundled`. `enclave-iroh serve -require-maximal` refuses to start otherwise.
- **Residual:** enforcement lives at the verifier's policy. A verifier that
  accepts non-maximal attestations gets no T8 protection. Does not help against
  T7 (a maximal-looking attestation can still be a self-signed lie from A2).

### T10 — Backdoored "published" build
- **Adversary:** A6
- **Impact:** AS4 at its root — the pinned cdhash corresponds to malicious code
- **Mitigation □ (out of scope for runtime attestation):** addressed only by
  reproducible builds (TA4), source review, dependency pinning, and
  notarization. Runtime attestation faithfully proves "the code with cdhash *C*
  is running"; it cannot prove *C* is trustworthy.
- **Residual:** fully out of scope here; noted so it is not assumed away.

### T11 — Stale attestation / version rollback
- **Adversary:** A1, A2
- **Impact:** AS5 — presenting an old, valid attestation for a superseded build
- **Mitigation ▢ (proposed):** the per-connection nonce (T6) plus a monotonic
  build/version field in the signed payload; the verifier pins the *current*
  acceptable cdhash set and rejects known-superseded ones.
- **Residual:** verifier must keep its pin set current.

### T12 — Enclave or hardware compromise
- **Adversary:** A4 (with a kernel/firmware break), A5
- **Impact:** AS1, AS5 — the whole model
- **Mitigation □:** none within scope; this is TA1.
- **Residual:** accepted as a trust assumption. A broken Enclave voids every
  key-custody claim.

## What the assurance actually is

The question decomposes into a ladder. Each rung is what you can *soundly claim*
to a peer, and against which adversary.

| Level | Claim | Provided by | Holds against |
|-------|-------|-------------|---------------|
| L0 | "Both ends are the same key; traffic is authentic and private." | iroh QUIC/TLS | A0, A1 |
| L1 | "The endpoint key can't be stolen at rest; the identity is stable." | enclaveiroh key custody (T1, T3) | A0–A3, A5 (at rest) |
| L2 | "The peer *self-reports* the published cdhash under a Hardened Runtime, bound to this live session." | proposed cdhash + channel-bound handshake (T6, T9) | A1 (replay), and A2 *only if A2 is honest* |
| L3 | "Only a binary signed by this Team, with this entitlement, reached the key." | keychain-access-group gate (T8) | A2/A3 lacking the team signature |
| L4 | "The peer *provably* runs the exact binary, even if adversarial." | **external root of trust — not macOS-native** | A2 |

L0–L3 are achievable with the mechanisms in `enclaveiroh` (L2/L3 need the
proposed handshake and the bundled path). **L4 is the one people usually mean by
"confident it's the published code," and it is exactly the rung `enclaveiroh`
cannot reach against a malicious peer (A2 / T5 / T7).**

## What remains open — reaching L4

L4 requires an attestation a peer *cannot forge about itself*, which means a
third party the peer does not control must vouch for the code. Options, none of
them native macOS:

- **Apple App Attest** (`DCAppAttestService`) — Apple's servers vouch that a
  hardware-backed key belongs to a genuine, unmodified instance of *your* App ID
  on genuine Apple hardware. This is real remote code attestation, but it is
  iOS/iPadOS/tvOS-family, not native macOS. Viable only if a peer can be an
  iOS-family app.
- **Confidential-computing TEE** (Intel SGX, AMD SEV-SNP, Intel TDX, AWS Nitro
  Enclaves) — the hardware measures the loaded code and signs the measurement
  with a vendor-CA-rooted key. Appropriate for *server* peers on the network.
- **TPM 2.0 remote attestation (DICE)** — an Endorsement Key rooted in a
  manufacturer CA attests measured boot + code on non-Apple hardware.

Each replaces "trust the peer's own signature" (T7) with "trust a vendor CA and
a measured-launch chain." Layering any of them under the iroh handshake — the
attestation signs the endpoint pubkey + nonce, exactly as in T6, but with a
CA-rooted quote instead of a self-held Enclave key — closes T5 against A2 and
reaches L4.

## Operational notes

- **First-run race:** two processes racing the very first persistent use can each
  generate a wrapping key under the same tag (a later `kSecMatchLimitOne` lookup
  then picks one arbitrarily), and `storeSecret`'s delete-then-add can interleave,
  producing a split-brain identity. Provision the persistent key once before
  fan-out; the ephemeral path is unaffected (each process is its own identity).

## Non-goals

- Proving trustworthiness of the *source* (T10) — only that a specific cdhash is
  running.
- Defending a peer against its own privileged local attacker beyond speed bumps
  (T2, A4/A5).
- Protecting against a broken Enclave or kernel (T12, TA1/TA2).
- Confidentiality of *metadata* (that two endpoints are talking, and when); iroh
  hides content, not the existence of a flow.

## Summary

`enclaveiroh` gives strong guarantees for AS1–AS3 (key custody, identity,
channel security) against network and local-unprivileged adversaries, and a real
if partial code gate (AS4, L3) via the Team-ID entitlement. It does **not**, and
on native macOS cannot, prove AS4 to L4 against a malicious peer, because the
attestation is self-signed by a key the peer controls (T7). "Confident messages
between the exact published Go code" is therefore achievable as *outbound
self-attestation* and as *"only a team-signed binary participates,"* but sound
*peer verification against an adversary* needs an external attestation root
(App Attest, a TEE, or a TPM) that macOS does not provide for native binaries.
