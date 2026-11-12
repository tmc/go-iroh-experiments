# irciroh

`irciroh` is IRC with no server. Identity is an iroh endpoint key, a channel
is an iroh gossip topic, and a channel message is a signed envelope
broadcast on that topic. Private messages go over a direct QUIC stream on
ALPN `irciroh/dm/1`.

The module is two layers:

- package `irciroh`, the peer-to-peer chat core: `Node`, `Channel`,
  `Member`, `Event`, `Ticket`. No IRC syntax appears here.
- `cmd/irciroh`, a local IRC server that any unmodified IRC client
  (irssi, WeeChat, HexChat, `nc`) connects to on 127.0.0.1. It translates
  IRC commands into calls on the core and core events back into IRC lines.

A channel name and an optional secret hash into the topic:

```
TopicID = blake3("irciroh/channel/v1\n" + fold(channel) + "\n" + secret)
```

A public channel has an empty secret, so anyone who knows the name and one
peer can join, which is IRC's model. A channel created with a secret is
invite-only in practice: the secret travels only in a ticket.

Every gossip message and every private-message frame is one postcard
envelope — version, kind, sender key, per-sender sequence number, sender's
clock, nick, text, and an Ed25519 signature over all of it. A receiver
drops an envelope whose signature fails, whose sender is not the peer that
delivered it when delivery was direct, whose sequence number it has
already taken or that falls 64 or more below the sender's highest, or whose
timestamp is more than five minutes from local time either way. Gossip may
reorder a sender's envelopes, so an earlier one that arrives late is still
taken once, though only the sender's latest envelope sets its nick. A nick
may not hold a space or a control character, and text may hold no control
character but tab, `\x01` and IRC's formatting codes, so no CR, LF, NUL,
DEL or C1; an envelope that breaks either rule is dropped, and never sent.
Envelopes are capped at 4 KiB; the bridge splits longer text, mirroring
IRC's 512-byte line limit.

Presence is a ping on join, on a new neighbor, and every 30 seconds. A
member of a public channel unheard for 90 seconds is dropped and reported
as a part with the reason `timeout`. A ping from a member that knows the channel topic carries
the topic text, so a joiner has it within one presence interval without a
request and reply.

Run the networked flow — two endpoints on loopback joining by ticket,
exchanging a message, a topic, a nick change, a private message, and a part
— with:

```sh
go test -run TestNetwork -v
```

## Sealed channels

`Node.Found` creates a **sealed** channel, whose gossip payloads are MLS
messages (RFC 9420) instead of signed envelopes. A public channel hides
behind its topic and its members are whoever is listening. A sealed
channel's members are the group's roster, and a member removed from it
cannot read what is said afterwards even though the bytes still reach it.

```
SealedTopicID = blake3("irciroh/sealed/v2\n" + fold(channel) + "\n" + founder + "\n" + secret)
```

Every payload on the topic is an MLS PrivateMessage — commits and
proposals as well as lines — so who is added, removed or rekeyed is read
only by members. The seal does not cover the traffic around it: each
message's group id (the channel name), epoch and content type are in its
header, sizes and timing are visible, and a gossip peer learns the
endpoint ids of the peers it connects to, which in a small channel is
most of the roster. The secret is in the derivation so that seeing even
that much takes a ticket. The Welcome never touches the topic: it goes
back to the joiner over the founder's invite connection.

The cost is silence. A joiner the founder refuses still gets an answer,
because it had the secret and reached the swarm; someone who never had it
cannot tell an empty topic from a channel that does not exist. Members
must also agree on the secret to meet at all, so rotating it founds a new
channel rather than rekeying this one.

Every leaf of the group carries the binding of the sibling `mlsiroh`
package: a credential naming the member's endpoint id, signed by that
endpoint key. So the roster is a list of endpoints you can dial, the sender
of a message is resolved from its leaf rather than from the transport that
delivered it, and the founder's admission policy is a
`func(key.EndpointID) bool`. A joiner presents its key package over a
connection nobody else can make, on ALPN `irciroh/invite/1`, and the
founder checks that the binding names the endpoint that dialed.

**The founder is the only member that commits.** MLS needs a total order on
commits per epoch — two members committing from one epoch fork the group
unrecoverably — and a serverless channel has nobody to impose one, so a
sealed channel does not ask for one. Joins and removals go through the
founder. The channel keeps working while the founder is away; only its
membership cannot change.

A member that misses a commit finds out from the epoch in the next message
header, which it can read without being able to decrypt, and recovers by
joining again — the same exchange as the first join, and the same one an
endpoint that lost its state makes. The founder removes an endpoint's
existing leaves in the commit that adds the new one, so a rejoin does not
leave the channel with one member listed twice.

Membership and presence are different questions here. `Channel.Members`
returns the roster; `Member.Seen` reports liveness. A member that has
stopped answering pings is still in the group and can still read, until the
founder's presence timeout turns into a removal.

A removal is not by itself a revocation. The removed endpoint still holds
the invite secret, which names nobody, and can rejoin with it — that is
what lets a member the network dropped come back. Keeping an endpoint out
is a separate decision: `Channel.Kick`, or `KICK` over the bridge, which
records the endpoint and refuses it readmission. It does not reach the
operator behind that endpoint, who can mint a fresh one; an admission policy passed to `Node.Found` is what does
that.

## Reaching other nodes

There is no network to join. A channel is a topic; two nodes are in the
same channel when they are in the same gossip swarm on it, and entering a
swarm takes a peer already in it — which is what a ticket carries.
Nothing discovers who else is on a channel, so the first meeting happens
out of band (someone sends you a ticket) and after that any member's
ticket lets the next person in. It is closer to a torrent swarm and its
magnet link than to IRC's global network.

A ticket is only as good as the address inside it. `Node.Addr` reports
what the endpoint knows it is reachable at, and **go-iroh disables relays
by default**, so an endpoint bound to the unspecified address knows
nothing and `Node.Ticket` returns `ErrNotReachable` rather than mint a
ticket that cannot be dialed. `cmd/irciroh` turns relays on (`-relay`,
default true), which is what lets a ticket work off the local network:

```
peer[0] addrs=[relay:https://…relay.n0.iroh.link./]
```

That is the whole address, on purpose. The endpoint also knows the IP
candidates it was discovered at, but a peer that dials the relay
negotiates a direct path from there, so putting them in the ticket buys
nothing — while costing the minter its home address, to everyone the
ticket is ever forwarded to, long after the join it was written for. A
ticket travels further than a connection does. IP candidates appear only
when there is no relay, where they are the only way to be reached.

With `-relay=false` only a directly routable peer can be reached, and
`-bind` must name a concrete address for a ticket to be mintable at all.

## Finding a channel by name

A ticket is how a first meeting happens, but handing one to everybody is
a poor way to run a public channel. `WithRendezvous` — `-rendezvous` on
the bridge, on by default — closes that:

```
rendezvous key = ed25519(blake3("irciroh/rendezvous/v1\n" + fold(channel) + "\n" + secret))
```

Everyone who can address the channel derives the same keypair, members
announce themselves under it through iroh's endpoint-discovery service,
and a join with no bootstrap peer resolves it to find someone to start
from. `/join #go` then works with nothing else.

Who can derive it is the point of the secret. A **public** channel
derives from its name, so anyone who knows the name can find it, which
is IRC's model. A **sealed** channel derives from its invite secret, so
only a ticket holder can resolve it — announcing one under its name
would publish precisely the roster that deriving the sealed topic from
the secret exists to hide. It also means a ticket keeps working after
the founder's address changes: the secret finds the channel again.

The record is a hint, not an authority. Anyone who can derive the key
can write one, so a joiner can be pointed at an endpoint that is dead or
never was a member — which costs it a dial, not a seat, because the
swarm admits whoever reaches it and a sealed channel admits only whom
the founder commits.

It is on by default in the command but off in the library, because it
publishes outside this machine: a node announcing a channel tells anyone
who looks up that name that it is there. `-rendezvous=false` opts out,
and then a join needs a ticket.

## Durable state

`WithStateDir` — `-state` on the bridge, by default a directory under the
user config directory — keeps two things across restarts: the endpoints
this node has kicked, and the invite secret of each channel it founded.
Neither is optional if a kick is to mean anything. A ban held only in
memory is undone by the next restart, and a founder that mints a fresh
secret on restart names a different topic, voiding every ticket it handed
out and leaving the ban nothing to bite on.

Those secrets are credentials: whoever reads one can join the channel it
names. The directory is 0700 and the file 0600, and each write is a
temporary file renamed into place, so a crash leaves either the old
contents or the new. What is *not* written is MLS group state — a disk
read later does not open anything anyone said. The price is that a
restarted founder re-founds: same name, same secret, same topic, a new
group. Members must leave and join again with the ticket; reconnecting
an IRC client to an existing bridge does not reset its old MLS group.

With no state directory the node keeps nothing and still works. It just
forgets.

A message sent in one epoch cannot be read in the next, so a sender keeps
what it said in the last minute and seals it again after
each epoch change; receivers drop the copies they already have by sequence
number. Old epoch keys are discarded, but compromise of the sender
during the resend window can expose its retained plaintext. A resent line
can arrive after lines said later, and carries the time it was said. It is not resent across a commit that adds
an endpoint, because the newcomer would read what was said before it
arrived: a message in flight across a join is still lost, and a client
sees a gap, as it would from a netsplit.

Members propose fresh encryption and signing keys every 15 minutes.
The founder commits these updates. This requires delivery and an available
founder; it is not a recovery deadline. The endpoint key must remain safe.
The founder retains its signing key because MLS excludes the committer's
own Update proposal.

From an unmodified IRC client, the JOIN key `seal` founds one and the
bridge notices back the ticket:

```
/join #vault seal
-!- irciroh: irciroh...
/join #vault irciroh...      # elsewhere
```

```sh
go test -run 'TestNetworkSealed|TestBridgeSealed' -v ./...
```

## Status and limits

This module is an experiment. Its wire formats and API may change.

- It builds against go-iroh v0.3.0. In that release a blocking connect
  can return before the handshake has authenticated the peer, so a
  member that rejoins a sealed channel after its founder restarts can
  have its invite request rejected. The fix is not in a released
  go-iroh.
- A join by name alone can form an island. The rendezvous record for a
  channel names one peer, and it is a hint that anyone who can derive
  the key may overwrite, so two groups can each find only themselves.
  A ticket carries bootstrap peers and avoids this; prefer tickets.
- Public channels are signed, not encrypted. Every member of the swarm
  can read them, and anyone who knows the name can join. Use a sealed
  channel for confidentiality.
- Recall is what live members still hold. Nothing is logged durably.

## Out of scope

Durable backlog and logs (recall is what a live member still holds, not
a log), channel modes beyond `+m` and the fixed `+nt`, services such as
NickServ, DCC, and server operators, of which there is nothing for one
to operate.

CTCP and IRCv3 are narrower than out of scope. ACTION passes through as
text and a direct VERSION, PING, CLIENTINFO or TIME query is answered;
the bridge offers the one IRCv3 capability `message-tags` and refuses the
rest.

Channel operators, `+m`, and kicks exist on sealed channels only. A
public channel has no founder and nothing to check a rank against, so a
mode or rank envelope there is ignored, and `WithQuiet` is a node's own
mute rather than a ban.

On a public channel, encryption beyond QUIC and the secret-derived topic
is also out of scope: gossip payloads are readable by every member, as in
IRC. Sealed channels are the answer to that. Catching a member up on the
commits it missed is out of scope even there — it rejoins instead.

## Protocol choices

- `Node.Private` yields `Event` values of kind `Message` rather than a
  separate `Message` type. The spec names both an `EventKind` constant
  `Message` and a type `Message`, which cannot coexist; the event kind
  wins, and `Event` already carries everything a private message needs.
- `Node.JoinTicket` is added. The spec's `Join` takes a channel name and
  bootstrap peers but no secret, so there is otherwise no way to join a
  channel whose topic is derived from one. `Join` is `JoinTicket` with an
  empty secret.
- `Node.Addr`, `Node.PeerAddr`, `Node.Endpoint`, and `Node.Channels` are
  added. `SendPrivate` takes a peer address, and the bridge has to obtain
  one: `PeerAddr` reports what the endpoint learned from the gossip
  connection to that peer.
- A join that carries bootstrap peers waits until the channel's gossip
  topic has a neighbor. A broadcast made before that goes nowhere, which
  makes an immediate `Say` after `Join` silently lossy.
- Sequence numbers come from one node-wide counter seeded from the wall
  clock rather than a counter per topic. It is still strictly increasing
  per sender per topic, and it does not regress across a rejoin or a
  process restart, which a per-topic counter starting at zero would.
- A topic learned from a presence ping is attributed to the peer that
  relayed it, and any topic envelope supersedes it. The spec's
  last-writer-wins rule by `(Time, Sender)` orders topic envelopes against
  each other, where authorship is known.
- Members are also re-announced when a new gossip neighbor appears, not
  only every 30 seconds, so a joiner and the members already present see
  each other at once rather than after a presence interval.
- The bridge answers a `TICKET <#channel>` command with a `NOTICE`
  carrying the channel's ticket, and `irciroh invite` is an IRC client
  that asks for one. RFC 1459 has no command for this, and the spec does
  not say how `invite` reaches a running bridge.
- `serve` takes an extra `-bind` flag for the iroh endpoint's UDP address,
  separate from `-listen`, which is the IRC address.
- Registration sends `422` (no message of the day) after `001`-`004`, and
  `333` after `332`, because clients expect both.
