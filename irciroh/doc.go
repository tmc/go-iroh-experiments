// Package irciroh implements IRC's chat model with no server.
//
// Identity is an iroh endpoint key, a channel is an iroh gossip topic, and
// a channel message is a signed envelope broadcast on that topic. Private
// messages travel over a direct QUIC stream on ALPN [ALPN]. No IRC syntax
// appears in this package; the command irciroh is a local IRC server that
// translates between an unmodified IRC client and a [Node].
//
// A channel name is hashed with its optional secret into a topic:
//
//	TopicID = blake3("irciroh/channel/v1\n" + Fold(channel) + "\n" + secret)
//
// A public channel has an empty secret, so anyone who knows the name and
// one peer can join, which is IRC's model. A channel created with a secret
// is invite-only in practice, because the secret travels only in a
// [Ticket].
//
// # Sealed channels
//
// [Node.Found] creates a sealed channel, whose gossip payloads are MLS
// messages (RFC 9420) rather than signed envelopes. A public channel
// hides behind its topic and its members are whoever is listening; a
// sealed channel's members are the group's roster, and a member removed
// from it cannot read what is said afterwards even though it still
// receives the bytes.
//
// What is sealed is everything the group says: the text, and the
// commits and proposals that add, remove and rekey members, which are
// encrypted like the text. What is not sealed is the traffic itself -
// its timing and sizes, each message's epoch and content type, and the
// endpoint ids of the gossip peers a listener connects to - and that is
// covered by the topic, which is derived from the invite secret. A
// ticket holder who never joins sees that much and no more.
//
// A removal does not keep anyone out on its own: the removed endpoint
// still holds the invite secret and can ask to join again, which is
// what lets a member that dropped off the network come back. Keeping an
// endpoint out is [Channel.Kick], and it is a separate decision from a
// removal.
//
// Every member is an iroh endpoint, because every leaf of the group
// carries the binding of [github.com/tmc/go-iroh-experiments/mlsiroh]:
// a credential naming the member's endpoint id, signed by that endpoint
// key. So a sealed channel's roster is a list of endpoints, the sender
// of a message is resolved from its leaf rather than from the transport
// that delivered it, and the founder's admission policy is written in
// endpoint ids.
//
// The founder is the only member that commits. MLS needs a total order
// on commits per epoch and a serverless channel has nobody to impose
// one, so a sealed channel does not ask for one: joins and removals go
// through the founder, over [InviteALPN]. The channel keeps working
// while the founder is away; only its membership cannot change. A member
// that misses a commit finds out from the epoch in the next message
// header, which it can read without being able to decrypt, and recovers
// by joining again. A message from the next epoch alone is not enough to
// say so, since it may only have overtaken its commit: it is held until
// the commit arrives, for ten seconds at most.
//
// A sealed channel and a public one can wear the same name, since a
// public channel's topic is derived from its name alone. So a name is
// never enough to say which channel is meant, and [Node.Join] refuses a
// name this node founded rather than answer with the public channel -
// there is no downgrade a caller could not have asked for explicitly.
// [Node.Found] is the way back onto a channel this node founded, and it
// returns the live channel when there is one: the founder's secret is
// kept, so the same channel comes back after a restart.
//
// Members propose fresh encryption and signing keys every quarter hour.
// The founder commits their updates, activating the new keys. Recovery
// requires delivery, an available founder, and an uncompromised endpoint
// key; the interval is not a deadline. The founder retains its signing
// key because MLS does not accept its own Update in its commit.
//
// A sealed channel's topic is derived from its founder and its invite
// secret: [SealedTopicID]. The secret is in there because the swarm
// does not hide its members from each other: a gossip peer learns the
// endpoint ids of the peers it connects to, so reaching the swarm has
// to take a ticket.
//
// # Reaching other nodes
//
// There is no network here to join: a channel is a topic, and two nodes
// are in the same channel when they are in the same gossip swarm on it.
// Entering a swarm takes a peer already in it, which is what a [Ticket]
// carries. Nothing discovers who else is on a channel, so a first
// meeting happens out of band - someone sends a ticket - and after that
// any member's ticket lets the next one in.
//
// A ticket supplies initial address hints. For sealed admission, a failed
// founder dial is retried by endpoint id when address lookup is configured.
// Both attempts share the admission deadline, and the lookup retry sends no
// duplicate request. Without lookup, the ticket needs a reachable address.
// [Node.Addr] reports
// what the endpoint knows it is reachable at, which with relays
// disabled and an unspecified bind address is nothing at all;
// [Node.Ticket] fails with [ErrNotReachable] rather than mint a ticket
// nobody can dial. Relays are what make an endpoint reachable from
// outside its own network, and go-iroh leaves them off by default, so a
// caller that wants its tickets to travel enables them
// (iroh.WithRelayMode) - as the command irciroh does.
//
// A ticket carries the relay alone when there is one, and the endpoint's
// IP candidates only when there is not. A peer that dials the relay
// negotiates a direct path from there, so the addresses would buy the
// ticket nothing; what they would cost is that a ticket names the
// address its minter was seen at, to everyone it is ever forwarded to,
// long after the join it was written for.
//
// # Finding a channel by name
//
// A ticket is how a first meeting happens, but it is a poor way to run
// a channel that is meant to be public: everyone who wants in has to be
// handed one. [WithRendezvous] closes that. A channel derives a keypair
// that anyone who can address it can derive too, members announce
// themselves under it through the endpoint-discovery service, and a
// joiner resolves it to find someone to bootstrap from. [Node.Join]
// with no bootstrap peers consults it, so a channel can be joined by
// name alone.
//
// Who "anyone who can address it" is depends on the channel. A public
// channel derives from its name, so anyone who knows the name can find
// it, which is IRC's model. A sealed channel derives from its invite
// secret, so only a ticket holder can resolve it - announcing one under
// its name would publish exactly the roster that deriving the sealed
// topic from the secret exists to hide. It also means a ticket keeps
// working when the founder's address changes, because the ticket's
// secret finds the channel again.
//
// A ticket that names peers is used as it stands; rendezvous is for a
// join that has nothing else. The record is a hint: anyone who can
// derive the key can write one, so a joiner may be sent to an endpoint
// that is dead or was never a member. Neither gains anything by it. A
// public channel admits whoever reaches its swarm, and a sealed one
// admits only who the founder commits, so a bad record costs a joiner a
// dial rather than a seat.
//
// Rendezvous is off unless asked for, because it publishes outside this
// machine: a node that announces a channel tells anyone who thinks to
// look up that name that it is there.
//
// # Durable state
//
// A [Node] given [WithStateDir] keeps two things across restarts: the
// endpoints it has kicked, and the invite secret of each channel it
// founded. Neither is optional if a kick is to mean anything. A ban that
// lived only in memory would be undone by the next restart, and a founder
// that minted a fresh secret on restart would name a different topic,
// voiding every ticket it had handed out and leaving the ban with nothing
// to bite on.
//
// The secrets are credentials: whoever reads one can join the channel it
// names. The directory is created 0700 and the file 0600, and the write
// is a temporary file renamed into place so a crash leaves either the old
// contents or the new. What is not written is MLS group state, so a disk
// read later does not open anything anyone said. The cost is that a
// restarted founder re-founds: same name, same secret, same topic, but a
// new group. Members must leave and join again through a ticket; old
// group state is not restored by reconnecting the IRC client.
//
// Without a state directory a [Node] keeps nothing and works anyway: a
// kicked endpoint rejoins after a restart, and a founder that restarts
// voids its tickets.
//
// # Envelopes
//
// Envelopes are the public channel's wire format and the private
// message's. A sealed channel carries a smaller record inside MLS, which
// authenticates the sender and rejects a replay within an epoch, leaving
// nothing for a signature to do. The record keeps a sequence number, so
// that a line sealed again after an epoch change is shown once, and the
// sender's clock, which is no reason to drop a line: one stamped more
// than five minutes ahead is shown, but counts as said on arrival when a
// mode, a rank or a topic goes to the latest statement.
//
// Every gossip message and every private-message frame is one envelope
// encoded with [github.com/tmc/go-iroh/postcard]: a version, a kind, the
// sender's public key, a per-sender sequence number, the sender's clock in
// unix milliseconds, the sender's nick, a text body, and an Ed25519
// signature over every preceding field. A receiver drops an envelope whose
// signature fails, whose sender does not match the peer that delivered it
// when delivery was direct, whose sequence number it has already accepted
// or that falls 64 or more below the highest it has accepted from that
// sender, or whose timestamp is more than five minutes from local time in
// either direction. Gossip may deliver a sender's envelopes out of order,
// so an earlier number that arrives late is still accepted once, though
// the nick it carries is not taken: only a sender's highest-numbered
// envelope names it. Envelopes are limited to [MaxEnvelopeSize] bytes;
// longer text must be split by the caller, mirroring IRC's 512-byte line
// limit.
//
// A nick may hold no space and no control character. A text body - a
// message, a topic, a parting reason - may hold tab, CTCP's \x01 and
// IRC's formatting codes (\x02 \x03 \x0f \x16 \x1d \x1e \x1f) and no
// other control character: no CR, LF or NUL, no other C0 control, no DEL
// and no C1 control. A receiver drops an envelope or a sealed note that
// breaks either rule, as it would one whose signature fails, and a node
// refuses to send one. Whatever renders a line next is never handed a
// line break its sender put there.
//
// # Presence
//
// A member broadcasts a presence ping on join and every 30 seconds. A
// member of a public channel not heard from for 90 seconds is dropped
// from [Channel.Members] and reported as [Parted] with the text "timeout". Nicks are claims, not
// reservations: two members may claim one nick and both are shown. A node
// never renames itself.
//
// On a sealed channel presence answers a different question than
// membership. [Channel.Members] returns the group's roster, and a member
// that has stopped answering pings is still on it and can still read
// what is said; [Member.Seen] is what reports liveness. The founder
// turns a presence timeout into a removal, so the two converge, but they
// converge from different directions and a caller that needs one should
// not read the other. A timeout by itself drops nobody from a sealed
// channel and costs nobody a rank; the member is reported as [Parted],
// with the text "removed", when the founder's commit takes it off the
// roster.
//
// A ping from a member that knows the channel topic carries the topic text,
// so a joiner learns it within one presence interval without a request and
// reply. A topic set by an explicit topic envelope always supersedes one
// learned from a ping; between explicit topic envelopes the last writer
// wins by timestamp, then by sender.
//
// # History
//
// A channel has no backlog: gossip delivers what is said while a member
// is listening and nothing else, which is IRC's model and is the wrong
// one for a program that joins, restarts, and joins again.
//
// [WithHistory] gives such a node the two halves of recall. It keeps
// the recent lines of the public channels it is in, as the signed
// envelopes they arrived in, and it asks the peers a join names for
// theirs. What comes back is replayed into the channel's event stream
// as [Replayed] events - never as [Message] or [Notice], so a renderer
// that has not been taught about history drops hearsay rather than
// showing it as speech. Each one names the key that signed it, which
// this node verifies, and in [Event.Via] the peer that served it, which
// it cannot. A peer can omit, reorder and repeat; the design makes that
// visible rather than pretending to prevent it.
//
// Sealed channels keep and serve nothing: their plaintext stays inside
// the group's key schedule.
//
// # Out of scope
//
// This is a chat core, not an IRC server implementation. Durable
// backlog (recall is what a live member still holds, not a log),
// channel modes beyond +m and the fixed +nt, services such as NickServ,
// and DCC are all out of scope.
//
// Two things here are narrower than out of scope. Of CTCP, ACTION
// passes through as text and a direct VERSION, PING, CLIENTINFO or TIME
// query is answered; nothing else is. Of IRCv3 the bridge offers exactly one
// capability, message-tags, and refuses every other request: a nick is
// borrowed and a key is held, so a client that can be told which key
// spoke is told, in a tag beside the nick rather than instead of it. It
// answers CAP whether or not anything is asked for, because a modern
// client will not finish registering until it has been told the
// negotiation is over.
//
// Server operators are out of scope, because every power IRC gives one
// is authority over a connection or over a server's configuration and
// there is neither here. Channel operators are in scope, and are a
// sealed channel's alone - see [Channel.Grant]. A sealed channel has the
// founder's endpoint in its topic derivation and MLS authenticates
// every sender, so "the founder said so" is something a member can
// check. A public channel derives its topic from its name, so it has no
// founder, nothing to check a claim against, and no operators; a mode
// or rank envelope there is ignored rather than honored on trust, and
// [WithQuiet] is what a node on one has instead.
//
// Moderation runs in three tiers, and they are not equally strong.
// Membership is cryptographic: [Channel.Kick] is an MLS removal and a
// key rotation, so the removed endpoint cannot read what is said next
// whatever software it runs. Ranks and modes are signed policy:
// [Channel.Grant] and [Channel.Moderate] are statements from an
// authority a member can verify, honored by every member running this
// code, which a member running its own can ignore - what answers that
// is a kick. Refusal is local: [WithQuiet] and the rate limits below
// need nobody's agreement at all. A design that blurred these would
// promise what the last one cannot deliver, and the failure it would
// produce is a roster that says removed while the key schedule says
// otherwise.
//
// Only the founder commits, so only the founder kicks, and only the
// founder grants or revokes [Operator]. An operator voices, devoices
// and moderates: statements it signs, not commits it cannot make.
//
// A rank and the moderated flag are absolute, not a change to apply:
// an envelope says what standing to hold, so a member that sees the
// same two grants in the other order ends up in the same place. Where
// two operators speak at once the later statement wins and a tie goes
// to the higher endpoint id, which is the rule a topic already
// follows. What that rule cannot do is make two members agree about a
// grant one of them never received; gossip has no acknowledgement, and
// re-granting is the repair.
//
// A rank lives on a roster entry and nowhere else, so it lasts exactly
// as long as the membership it names: a member that drops off the
// network and rejoins comes back ordinary, and a grant that arrives
// before the commit adding its target is dropped rather than held. Both
// lose standing rather than invent it, which is the same direction the
// rate limiter errs in, and both are repaired by granting again.
//
// # Abuse
//
// What bounds a flood is that every node limits what it will spend on
// any one sender, unilaterally. There is nothing to
// agree on and nobody to appeal to, so a channel is protected because
// each member independently refuses the same flood.
//
// A limit per sender is only worth what an identity costs, and an
// endpoint id costs a keypair. So a sender this node has not heard from
// starts with one message and a slow refill and earns its way to the
// settled numbers over a warm-up, which is what makes minting an
// identity per message pointless. The only thing a stranger can offer
// towards that is presence: on a public channel every other signal is
// one the sender writes about itself.
//
// Announcing yourself is charged separately from speaking, because
// presence and speech are different floods. A member's own join and
// ping would otherwise spend the newcomer budget before it said a word,
// which would leave the choice between a limit worth having and a
// channel anyone can join and talk on. Presence is periodic, so its
// limit is read off the interval it is sent on and never binds on a
// member sending it as the protocol asks.
//
// A sealed channel skips the warm-up, because its members passed a
// door. The founder checked the invite secret before committing
// anybody, so the identity was not free and charging for it twice would
// only tax the people who paid. That is the whole of the standing this
// package keeps, it is never written down, and a node that forgets a
// sender treats it as a stranger again - erring towards forgetting
// standing rather than towards inventing it.
//
// A public channel has the weaker half of this. Its topic is derived
// from its name alone, so it is discoverable by guessing, anyone who
// finds it can speak, and a removal means nothing because the endpoint
// simply returns. It gets a rate limit with a warm-up, a bounded
// roster, and nothing else. A sealed channel is the answer: its topic
// is derived from an invite secret, so it cannot be found without a
// ticket, and its roster is an MLS group only the founder admits to.
//
// On a public channel, encryption beyond QUIC and the secret-derived
// topic is also out of scope: gossip payloads are readable by every
// member, as in IRC. A sealed channel is the answer to that, and it has
// its own limits. A message sent in one epoch cannot be read in the
// next, so a sender seals what it said recently again after each epoch
// change and receivers drop the copies they already have; no old
// epoch's keys are kept to do it. That does not cross a commit that
// adds an endpoint, since the newcomer would read what was said before
// it arrived, so a message in flight across a join is still lost; IRC
// has no backlog, so a client sees a gap, as it would from a netsplit.
// A channel whose founder is gone cannot change its membership. One
// committer is the supported mode by decision: MLS needs a total order
// on commits and a serverless channel has nobody to impose one, so
// ordering is a separate design, and handing the founder's role on is
// the next step if a founder's absence starts to matter. And nothing
// here catches a member up on the commits it missed: it rejoins
// instead.
package irciroh
