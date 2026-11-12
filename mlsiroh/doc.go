// Package mlsiroh implements a Delivery Service and an Authentication
// Service for MLS over iroh.
//
// RFC 9420 defines a group messaging protocol and leaves two services
// undefined: a Delivery Service, which moves protocol messages between
// members, and an Authentication Service, which binds a signature key
// to an identity. This package implements both, and the second one
// nearly disappears. MLS cipher suite 1 signs with Ed25519 and an iroh
// endpoint is an Ed25519 key, so a member can present a credential
// whose identity is its own endpoint id and sign, with the endpoint
// key, a binding over the rotatable signature key in its leaf. A peer
// that completed the QUIC handshake has already authenticated the key
// that signed that binding, so there is no directory to consult and no
// certificate to chain.
//
// There is no shared directory either. Each client serves its own key
// packages over its own ALPN, which is what makes the consume-once
// rule of RFC 9420, Section 10, enforceable: the owner is the only
// authority over its own pool.
//
// Both ways into a group are served. A member fetches a newcomer's key
// package with [FetchKeyPackage], commits the Add, and hands the
// Welcome to [DeliverWelcome]; or a newcomer fetches the group with
// [FetchGroupInfo] and commits itself in with
// [github.com/tmc/mls.Client.JoinExternal]. The second is the one the
// transport improves: the whole admission decision is a
// func([github.com/tmc/go-iroh/key.EndpointID]) bool, because the
// caller is authenticated before the request is read. There is no
// invitation to deliver and no token to mint.
//
// # What this does not do
//
// This package does not implement the MLS group state machine. It
// moves KeyPackage, Welcome, and GroupInfo messages and binds them to
// endpoint identities; the confidentiality of a group comes from an
// MLS client driving github.com/tmc/mls. See the mls-iroh-demo command
// for the composition.
//
// It supports groups with one committer, by decision. MLS forks a group
// unrecoverably when two members commit from the same epoch, so it
// needs a total order on commits, and a delivery service over iroh has
// nobody positioned to impose one. Ordering commits from several
// members is a separate design and is not part of this package. An
// application that cannot wait out an absent committer can have the
// committer hand the role to a successor, which keeps one committer at
// a time.
//
// # Security
//
// The binding ties a member's MLS credential to a stable iroh endpoint
// id. That is what removes the need for a separate authentication
// service, and it means anyone who sees two groups' key packages,
// GroupInfo, or ratchet trees can tell that one endpoint is in both.
// RFC 9750, Section 8.2.4, treats that as a real privacy loss. It is
// an accepted trade, not an oversight: an identity you can verify from
// the transport is an identity you can correlate. An application whose
// members must be unlinkable across groups must not use this binding.
//
// Serving a GroupInfo discloses the group's full membership roster,
// every member's credential, and the epoch to the caller, and its
// external_pub extension lets the caller mount an external commit.
// [Directory.PublishGroupInfo] therefore admits nobody unless given a
// policy.
//
// A Welcome must not be delivered until the commit that produced it is
// known to have been accepted: see [DeliverWelcome].
//
// A GroupInfo fetched from a directory is checked against the group id
// that was asked for, against its own signature, and against the
// endpoint that served it. MLS checks a GroupInfo only for internal
// consistency - the tree against the group context, the signature
// against a leaf of that same tree - so a whole group can be fabricated
// and still verify. Binding it to the transport is what makes a fetch
// name a particular group; see [FetchGroupInfo]. A directory makes the
// same check on [Directory.PublishGroupInfo], so it never serves a
// GroupInfo its own endpoint did not sign.
//
// Fetching a key package spends it, so an endpoint whose pool anyone
// may draw from can have it emptied, and kept empty, by anyone who can
// dial it. Real joiners then see StatusExhausted. A directory bounds
// fetches per endpoint and in total per minute whether or not anyone
// configured it, because the endpoint most likely to be drained is the
// one that never considered it; see [Directory.LimitKeyPackages]. The
// bound per endpoint is no defense against a caller with many endpoint
// ids, which cost nothing to make. The total is, at the price of
// availability: such a caller can spend everyone's share. An endpoint
// that must stay addable under that attack says who may add it, with
// [Directory.AdmitKeyPackages]. The same holds for delivered Welcomes.
//
// A Welcome is routed only if it names a key package this directory
// served and whose lifetime has not long passed; the served key
// packages are in the [Journal], so routing survives a restart. A
// directory accepts a few Welcomes per served key package, bounds how
// much of its queue one sender may hold, and rate-limits deliveries as
// it does fetches. Answers differ for a reference it served and one it
// did not (ok against not_found), so a caller that already knows a
// key package reference can learn whether this directory served it and
// still routes it. That is little: the key package's credential already
// names its endpoint, and probing is rate-limited.
//
// The endpoint key signs in two domains. MLS content is signed under
// RFC 9420's SignWithLabel, which covers a label and a version string
// as well as the content, while go-iroh's key.SecretKey.Sign is raw
// Ed25519 over whatever bytes a caller hands it. Nothing here or in
// irciroh gives the raw signer attacker-chosen bytes, so the domains do
// not meet today. A caller that adds such a use is responsible for
// making sure its own messages cannot be read as an MLS signature
// input; the labelling only separates the domains as long as one side
// of the pair stays closed.
//
// # Standards
//
// The credential is the multi-credential of
// draft-ietf-mls-extensions-08, Section 6.5, as implemented by
// github.com/tmc/mls/multicred. Its code points are those the draft
// suggests and IANA has not assigned, so they may move; a change is a
// wire break.
package mlsiroh
