# mlsiroh

MLS delivery and authentication over iroh.

[RFC 9420](https://www.rfc-editor.org/rfc/rfc9420) specifies a group messaging
protocol and deliberately leaves two services undefined: a **Delivery Service**,
which moves protocol messages between members, and an **Authentication Service**,
which binds a signature key to an identity. This package implements both, and the
second one nearly disappears.

MLS cipher suite 1 signs with Ed25519. An iroh endpoint *is* an Ed25519 key. So a
member presents a credential whose identity is its own endpoint id and signs — with
the endpoint key — a binding over the rotatable signature key in its leaf. A peer
that completed the QUIC handshake has already authenticated the key that signed that
binding. There is no directory to consult and no certificate to chain.

There is no shared directory either. Each client serves its own key packages over its
own ALPN, which is what makes MLS's consume-once rule enforceable at all: the owner is
the only authority over its own pool.

```
go run ./cmd/mls-iroh-demo -v
```

```
alice fetched a key package bound to ddbc31fcf0
alice committed: epoch 0 -> 1
bob got a welcome from 6bbcd460e4 and joined at epoch 1
both agree on epoch authenticator 57c34b74d9658fb6

a relay sees: group "mls-iroh-demo" epoch 1 format mls_private_message, 169 bytes of ciphertext
bob read: "hello from alice, over iroh"
bob resolves the sender to endpoint 6bbcd460e4

alice publishes the group to 2d8d935c84 and to nobody else
carol committed herself in: epoch 1 -> 2, all three agree on 7e4ef4fe53828d64
```

## The binding

The credential is the multi-credential of
[draft-ietf-mls-extensions-08](https://datatracker.ietf.org/doc/draft-ietf-mls-extensions/),
Section 6.5, as implemented by `github.com/tmc/mls/multicred`. A member's leaf
carries a weak multi-credential holding one binding: a basic credential whose
identity is the 32-byte endpoint id, signed by that endpoint key over the leaf's
own signature key.

The leaf key is *not* the endpoint key. That is the point. RFC 9420 rotates a
member's leaf signature key through Update proposals, and RFC 9750 depends on that
rotation to recover from a compromised signing key. Pinning the leaf key to a
permanent network identity would make rotation impossible. Instead the endpoint key
*certifies* the leaf key, and a member rotating its leaf signs a fresh binding with
the same endpoint key — so every other member still resolves it to the same endpoint.

A commit cannot do that. RFC 9420 gives a commit no way to change a leaf signature
key: the update path copies the old leaf and replaces only its encryption key. So the
binding survives every commit for free, and rotation is an Update proposal whose leaf
node the member builds itself. `SignUpdate` builds it — new signature key, new
encryption key, fresh binding, signed over the group id and the member's own leaf
index — and the member sends it with `Group.ProposeUpdate` for someone else to
commit, because Section 12.2 forbids a committer from carrying its own Update.

## The protocol

ALPN `mlsiroh/ds/1`. One request per stream, delimited by half-close, encoded in the
MLS presentation language so the experiment carries one wire language throughout.

| op | request | response |
|---|---|---|
| `fetch_key_package` | cipher suite | an `MLSMessage` carrying a `KeyPackage` |
| `deliver_welcome` | an `MLSMessage` carrying a `Welcome` | empty |
| `fetch_group_info` | group id | an `MLSMessage` carrying a `GroupInfo` |

A request is a version and an op, then the op's body. The directory reads the op
before the body and bounds the body by the op, so only `deliver_welcome` may be large,
and only a few of those are read at once.

Statuses: `ok`, `not_found`, `exhausted`, `malformed`, `unsupported`, `unavailable`.
`exhausted` means a limit refused the request: an empty pool, a policy, a rate, or too
many Welcomes for one key package. Only `unavailable` — a journal that would not
write, a full queue, a directory shutting down, a policy that panicked — invites a
retry. In Go the statuses match `ErrNotFound`, `ErrExhausted`, and `ErrUnavailable`
under `errors.Is`.

`deliver_welcome` carries no recipient. The directory matches the Welcome's
`new_member` references against the key packages it has served, which the journal
records with their init keys and lifetimes — the routing key is already in the
protocol, so naming the recipient out of band would be a side channel. A Welcome
naming a key package the directory never served, or one whose lifetime ended more than
a day ago, answers `not_found`. That does tell a caller holding a reference whether
this directory served it; the key package's credential already names its endpoint,
and probing is rate-limited.

There are two ways into a group and the protocol serves both. A member fetches a
newcomer's key package, commits the Add, and delivers the Welcome; or a newcomer
fetches the group's `GroupInfo` and commits itself in with `Client.JoinExternal`,
which is what the `external_pub` extension is for (RFC 9420, Section 12.4.3.2). The
second way is the one iroh improves: the entire access decision is `func(key.EndpointID)
bool`, because the caller of `fetch_group_info` is authenticated by the transport.
There is no invite to deliver and no token to mint. A `GroupInfo` describes one epoch
and the join ends it, so each one admits a single joiner; publish the next epoch's to
admit another, and withdraw the old one with its epoch, so that a withdrawal racing a
newer publication leaves the newer one in place.

## What this does not do

It does not implement the MLS group state machine. It moves KeyPackage, Welcome, and
GroupInfo messages; the confidentiality of a group comes from an MLS client driving
`github.com/tmc/mls`. `cmd/mls-iroh-demo` is the composition, and every line of group
logic in it is an `mls` call.

**A group has one committer.** That is the supported mode, by decision rather than as
a gap awaiting a fix. MLS needs a total order on commits per epoch or the group forks
unrecoverably: two members commit from epoch N, each derives a different epoch secret,
and neither can read the other again. A delivery service over iroh has nobody
positioned to impose that order, and nothing that uses this package needs one:
irciroh's sealed channels have the founder as sole committer. Publishing a GroupInfo
hands one epoch's commit to one external joiner, so the committer does not commit from
that epoch while it is published.

Ordering commits from several members is a separate design with its own choices — a
`tlogiroh` log in which the first valid commit per epoch in log order wins, a quorum
certificate per epoch, or a committer drawn by lot from the epoch's exporter secret
with a certificate to settle races — and it is future work, not part of this package.
An application for which a missing committer matters has a cheaper step first: the
committer signs the role over to a successor, which keeps one committer at a time.

## Security

The binding ties a member's credential to a stable endpoint id, so anyone who sees two
groups' key packages, GroupInfo, or ratchet trees can tell that one endpoint is in
both. RFC 9750 treats that as a real privacy loss. It is an accepted trade: an identity
you can verify from the transport is an identity you can correlate. Applications whose
members must be unlinkable across groups must not use this binding.

Serving a GroupInfo discloses the full membership roster to the caller and, with
`external_pub`, lets the caller mount an external commit. `PublishGroupInfo` admits
nobody unless given a policy.

Fetching one is checked on the other side too. MLS verifies a GroupInfo only against
itself — the tree against the group context, the signature against a leaf of that same
tree — so a whole group can be fabricated and still verify. `FetchGroupInfo` therefore
verifies the signature and checks the two things the transport knows and MLS does not:
that the GroupInfo names the group that was asked for, and that its signer is the
endpoint that served it. `PublishGroupInfo` refuses a GroupInfo its own endpoint did
not sign.

Fetching a key package spends it. An endpoint whose pool anyone may draw from can have
it emptied, and kept empty, by anyone who can dial it; real joiners then see
`exhausted`. A directory therefore admits a bounded number of fetches per endpoint and
in total per minute even when nobody configured one — `Directory.LimitKeyPackages`
changes the bounds — and `Directory.AdmitKeyPackages` gates the pool by caller on top
of that. The bound per endpoint is no defense against a caller with many endpoint ids,
which cost nothing to make. The total bound is, at the price of availability: such a
caller can spend everyone's share. An endpoint that must stay addable under that
attack needs the policy. Welcome delivery is bounded the same way, plus a cap per key
package and a share of the queue per sender.

Consume-once is keyed on the init key as well as the key package reference, because
re-signing a key package with a new lifetime gives it a new reference and the same init
key. The journal records both, one synced line per served key package, and a line torn
by a crash is cut off when the journal is opened.

`NewClient` configures MLS's `SameIdentity` callback to compare endpoint keys.
Branching and reinitialization therefore recognize the same endpoint after its
leaf signature key changes. MLS verifies the credential bindings separately.

An endpoint that lost its group state and rejoins externally can end up holding two
leaves. `JoinExternal` removes a prior leaf only when its signature key matches the
joiner's. With a fresh signature key, use `Leaves` to identify stale leaves and have
the group's committer remove them. `JoinExternal` does not accept arbitrary Remove
proposals, and `SameIdentity` does not change how it finds the prior leaf.

A Welcome must not be delivered until the commit that produced it is known to have been
accepted (RFC 9420 §14). `DeliverWelcome` documents this; the caller enforces it.

The draft credential code points are not IANA assignments and may move. A change is a
wire break.

## Status

Experiment. `go.mod` requires an unreleased `github.com/tmc/mls`; see `go.work` for the
local replace.

## Serialized sessions

`NewSession` takes exclusive ownership of an MLS group. Its mutex serializes
ratchets and epoch transitions. Use `Reserve` to authorize one endpoint's
external join, send the returned GroupInfo only to that endpoint, and pass the
commit to `Accept` with the connection's authenticated endpoint ID. Reservations
expire and block competing commits. Acceptance returns the epoch and SHA-256
hash of the exact wire message. The joiner checks `Receipt.Matches` before
using its provisional group.

A session requires valid endpoint bindings and one leaf per endpoint. Updates
preserve endpoint identity. `Rotate` retains fresh encryption and signing keys;
another member commits the proposal before those keys become active. MLS keeps
signers per group epoch, so rotation does not mutate a shared client. Owners use
`Receive` to accept authenticated member messages and Update proposals while
rejecting member commits; followers use `Handle` for the owner's ordered commits.

Sessions and Welcome queues are volatile. A successful `DeliverWelcome` only
acknowledges enqueueing; the recipient must separately acknowledge its joined
epoch. Restart creates a fresh random group incarnation. `FileJournal` persists
only consumed key packages, requires one writer process, and refuses malformed
complete records instead of forgetting them.

The [interactive example](examples/groupchat/README.md) runs separate owner and
member processes with endpoint-bound invitations, bidirectional chat, key
rotation, and retries for interrupted connections. Run its one-process smoke
demonstration with:

```
GOWORK=off go run ./examples/groupchat demo
```

It uses go-iroh v0.3.0 and the local `tmc/mls` credential-validation and staged
signing-key APIs. The MLS replacement remains local until that revision is
published. See [the example](examples/groupchat/README.md) for its scope.
