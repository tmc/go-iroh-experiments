# enclaveiroh attestation handshake (T6) — protocol spec

Status: **draft v1**, co-designed by sessions 35B3 and 8454. This is the spec
half of the T6 channel-bound attestation handshake from
[THREAT-MODEL.md](THREAT-MODEL.md); it is reviewable apart from the code. Where
this document and the code disagree, this document is the intended behavior.

## Goal

Raise a connection from **L1** (custodied identity, iroh channel security) toward
**L2/L3**: each side proves, over the exact authenticated channel that carries
application data, that it self-reports a specific code identity (cdhash, Team ID,
code-signing posture) under a Secure Enclave signature bound to *this* session.
This closes T6 (replay, cross-channel transplant, reflection) and moves T9
enforcement into verifier policy. It does **not** close T7: all claims remain
self-reported by the peer's process, so a Maximal-looking attestation from an A2
adversary is still possible. The handshake narrows *who can lie*, it does not
remove lying.

## Placement — in-connection, first bidirectional stream

The handshake runs on the **first bidirectional stream of the application
connection**, before any application stream proceeds. It is *not* a separate
attestation connection on a dedicated ALPN.

Rationale (accepted from 8454's proposal): a separate attestation connection can
only be correlated to the app connection by endpoint ID, which reintroduces a
cross-connection transplant surface — attest on connection 1, serve modified
behavior on connection 2 from a different process holding the same endpoint key
(the split-brain / shared-key case). Running in-connection binds the claim to the
precise channel the app data flows on. A config knob gates app streams on
handshake completion.

Integration consequence: the handshake operates at the `*iroh.Conn` level
(`RemoteID`, `ALPN`, `Side`, `OpenStreamSync`, `AcceptStream` — all verified
present in go-iroh aaac36baa54e). The demo's current `serveEcho` flattens streams
through `ListenStreams`, which loses the per-connection boundary; the serve path
is restructured to accept `*iroh.Conn`, run the handshake on the first stream,
then hand later streams to the app.

## Channel binding

iroh's TLS already mutually authenticates both endpoints' ed25519 keys, so the
**ordered endpoint-ID pair is the authenticated channel identity**. No TLS
exporter is exposed, and none is needed: binding the claim to both endpoint IDs
plus fresh mutual nonces binds it to this channel and this session.

## Messages

Length-prefixed JSON frames on the attestation stream. Dialer speaks first.

1. **Hello** (both directions):
   `{"v":1, "nonce":"<32B base64>", "mode":"mutual"|"prove"|"verify"}`
   - `prove` — I attest but do not require one from you.
   - `verify` — I require your attestation but send none (a non-darwin peer that
     cannot produce an Enclave attestation participates as verifier-only).
   - `mutual` — both.
   - **Mode compatibility (added):** the pair is validated after Hello exchange.
     `verify`×`verify` yields no attestation either way — that is an explicit L0
     result, reported as such, not silently treated as success. A side in
     `verify`/`mutual` facing a peer that sends no attestation (peer `verify`)
     gets `ok:false` unless its policy sets `AllowUnattested`. The full matrix is
     in the code and tested.

2. **Attestation** (from any side whose mode attests): the signed Claim below.

3. **Result** (both directions): `{"ok":bool, "reason":string}`. Advisory only,
   **not signed** — the authoritative outcome is each side's own local verdict
   over the peer's signed Claim. Result exists so a rejected peer learns why
   before the connection closes with a protocol error.

## Claim

The signed unit. Fields:

| Field | Meaning |
|-------|---------|
| `context` | literal `"enclaveiroh-attest/1"` — domain separation |
| `role` | `"dial"` \| `"serve"` (from `Conn.Side`) — kills reflection |
| `local_endpoint` | signer's own endpoint ID |
| `remote_endpoint` | the peer's endpoint ID as the signer sees it |
| `alpn` | `Conn.ALPN()` — binds to the application protocol |
| `nonce_self` | the signer's Hello nonce |
| `nonce_peer` | the peer's Hello nonce (transcript binding) |
| `cdhash` | code-directory hash, hex (csops `CS_OPS_CDHASH`=5) |
| `team_id` | signing Team ID (csops `CS_OPS_TEAMID`=14) |
| `cs_flags` | code-signing flags, uint32 (csops `CS_OPS_STATUS`=0) |
| `bundled` | ran inside a signed `.app` |
| `ephemeral_key` | endpoint key is ephemeral |
| `attest_key` | X9.63 hex of the Enclave attestation public key |
| `time` | RFC3339 |

### Signature encoding — length-prefixed binary, not JSON re-marshal

**Decision (35B3 counter to open question 2): the signature covers a canonical
length-prefixed binary serialization of the Claim fields, not a JSON re-marshal.**

Prior art in this repo: `x402iroh`'s `signingMessage` already length-prefixes each
field under a domain string precisely to make the signed message unambiguous:

```go
for _, f := range []string{signingDomain, network, a.From, ...} {
    b = binary.AppendUvarint(b, uint64(len(f)))
    b = append(b, f...)
}
```

The T6 Claim is a security-critical channel binding, so the two failure modes a
signed payload must avoid both matter here:

- **Field injection / ambiguity** — concatenating `team_id ‖ cdhash` without
  length prefixes lets a crafted `team_id` shift the boundary. Length prefixes
  (uvarint length before each field, all under the `context` domain string)
  remove it.
- **Marshal-determinism coupling** — signing a JSON re-marshal couples signature
  validity to `encoding/json`'s output being byte-identical forever. Fine for the
  live handshake (both sides run one binary), but a latent footgun. A fixed binary
  layout has no such dependency.

Canonical layout: `uvarint(len)‖bytes` for each field in the table order, with
`cs_flags` as a fixed 4-byte big-endian value, `bundled`/`ephemeral_key` as single
bytes. String fields are signed as their **encoded wire forms** (base64 nonces,
hex hashes and keys, endpoint-ID strings) — the length prefixes already make
boundaries unambiguous, and signing the encoded forms keeps `SigningBytes`
total (no decode errors). The wire **envelope** stays JSON (consistent with the
existing record and easy to read); only the *signed bytes* are the canonical
binary.

The existing session-attestation record in `attest.go` keeps its JSON-re-marshal
signature: it is a self-contained offline audit artifact with no channel-binding
and no adversarial field-injection surface, so the two schemes coexist with
documented rationale rather than one being retrofitted onto the other.

## Verifier checks (cheap/structural first, then policy)

1. Signature verifies against the embedded `attest_key` (stdlib ECDSA over the
   canonical binary — portable, runs on any platform).
2. `context` and `v` exact match; `role` is the complement of mine; `alpn`
   matches the connection.
3. Channel binding: `local_endpoint == Conn.RemoteID()`,
   `remote_endpoint ==` my own endpoint ID.
4. Freshness: `nonce_peer ==` the nonce I sent this connection; `nonce_self ==`
   the Hello nonce the peer sent.
5. Policy (all optional; the caller's dial chooses L2 vs L3):
   - `RequireMaximal` — `cs_flags` satisfies the `codeSigning.Maximal()` predicate
   - `RequireBundled`, `ForbidEphemeralKey`
   - `AllowedTeamIDs`, `AllowedCDHashes` — pin sets
   - `AttestKeyPin` — exact pins, or a TOFU callback the app supplies. **TOFU
     caveat:** trust-on-first-use defends against a key *changing*, not against
     impersonation on first contact; document it at the call site.
   - `AllowUnattested` — accept a peer that sent no attestation (explicit L0).

## What it closes vs. the threat model

- **T6** — fully: replay (`nonce_peer`), cross-channel transplant (in-connection
  + endpoint-ID binding), reflection (`role` + `remote_endpoint`). The original
  sketch `H(nonce ‖ pubkey ‖ …)` covered neither reflection nor the second
  endpoint ID.
- **T9** — moves into `Policy` as verifier code (`RequireMaximal` at accept time),
  not just a local start-time flag.
- **T11** — partially: `AllowedCDHashes` is the rollback lever.
- **T7** — unchanged and stays documented: every claim is self-reported.

## Self vs peer gates (open question 4)

`-require-maximal` (self, start-time: refuse to run if *my* posture is weak) and
`Policy.RequireMaximal` (peer, accept-time: refuse a weak peer) stay **separate**.
They answer different questions — "am I hardened" vs "do I trust you" — and folding
them would conflate self-hygiene with peer-trust.

## API surface

```go
// codeidentity.go (+ _darwin.go / _other.go)        (owner: 8454) — LANDED
type CodeIdentity struct { CDHash []byte; TeamID, SigningID string; Flags uint32 }
func LocalCodeIdentity() (CodeIdentity, error)        // csops; ErrUnsupported off-darwin
func MaximalFlags(flags uint32) bool                  // portable flag predicate

// claim.go — claim + policy + portable verify       (owner: 8454) — LANDED
type Claim struct { ... }
func (c Claim) SigningBytes() []byte                  // canonical length-prefixed binary
func VerifyClaimSignature(c Claim, sig []byte) error  // stdlib ECDSA, any platform
func VerifyClaim(c Claim, wantRole string, self, peer key.EndpointID,
	alpn string, selfNonce, peerNonce []byte) error   // structural+binding+freshness
type Policy struct { ... }
func (p Policy) Check(c Claim) error

// handshake.go                                       (owner: 35B3)
type Mode int // Mutual | Prove | Verify
type HandshakeConfig struct { Signer Signer; Identity CodeIdentity; Policy Policy; Mode Mode }
type PeerAttestation struct { Claim Claim; /* verified */ }
func Handshake(ctx context.Context, conn *iroh.Conn, cfg HandshakeConfig) (*PeerAttestation, error)
```

Command wiring (owner 35B3): `serve`/`dial` gain `-attest-peer` and policy flags
(`-require-peer-maximal`, `-pin-cdhash`, `-pin-team`, `-pin-attest-key`); the
offline session record gains the peer's verified Claim so it shows what was
checked.

## Division of labor (Option A)

- **8454:** `codeidentity_darwin.go`/`_other.go` (csops CDHASH/TEAMID — blob
  formats verified empirically first), the portable Claim/Policy/`VerifyClaim`
  core + `SigningBytes`, and the test suite: a pure-Go fake `Signer` (ECDSA, so
  protocol tests run on linux/CI) + negatives (replay, reflection, swapped
  endpoint IDs, wrong nonce, tampered flags, policy rejections, mode matrix).
- **35B3:** `handshake.go` (stream protocol, `*iroh.Conn` integration, mode
  negotiation), the serve-path restructure, cmd wiring, and THREAT-MODEL/ATTEST
  updates. Owns all existing files.
- **Sequencing:** 8454 lands codeidentity + Claim/Policy/verify first (no deps on
  35B3); 35B3 builds `handshake.go` on top; 8454 follows with the e2e loopback
  test.

## Open questions — resolved in this draft

1. In-connection vs dedicated ALPN → **in-connection** (transplant argument
   accepted).
2. JSON re-marshal vs length-prefixed binary signing → **length-prefixed binary**
   (x402iroh prior art; decouples from marshal determinism; injection-safe).
3. Sign the Result? → **no** (advisory; local verdict is authoritative).
4. Fold `-require-maximal` into peer Policy? → **no** (self vs peer are
   orthogonal).

Added for review: the **mode-compatibility matrix** (esp. `verify`×`verify` = L0)
and the **TOFU first-contact caveat**.
