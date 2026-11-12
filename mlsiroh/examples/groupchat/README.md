This example runs an owner and one invited member as separate processes. The
owner orders commits; both sides can send encrypted chat messages. Endpoint
keys survive a process restart, but MLS state does not.

Build from the `mlsiroh` module:

```sh
mkdir -p ~/tmp/mls-chat
GOWORK=off go build -o ~/tmp/mls-chat/groupchat ./examples/groupchat
```

First create the member's endpoint identity:

```sh
~/tmp/mls-chat/groupchat identity -key ~/tmp/mls-chat/member.key
```

Copy the printed endpoint ID. In the owner's terminal, authorize that identity
and create an invitation:

```sh
~/tmp/mls-chat/groupchat owner \
  -key ~/tmp/mls-chat/owner.key \
  -allow MEMBER_ENDPOINT_ID \
  -invite ~/tmp/mls-chat/invite.json
```

Wait for `invitation ready`. In the member's terminal:

```sh
~/tmp/mls-chat/groupchat member \
  -key ~/tmp/mls-chat/member.key \
  -invite ~/tmp/mls-chat/invite.json
```

Once the member joins, type messages in either terminal. The member can enter
`/rotate` to generate new encryption and signing keys. The owner commits that
Update, and the member activates the keys after receiving the commit. `/quit`
or Ctrl-C exits. Ctrl-C also stops a member waiting for a disconnected owner.

The invitation expires after ten minutes and is bound to the member's endpoint.
Transfer it through a trusted channel: it also tells the member which owner to
trust. Identity and invitation files are created with mode 0600. Invitations
are not overwritten; choose a new filename when starting a fresh owner.

The default UDP address is loopback. For a direct connection between hosts,
use an owner `-bind HOST_IP:PORT` and transfer the invitation to the member's
machine. Create the member key on that machine, and send only its printed ID
to the owner. The advertised owner address must be reachable. Relays and NAT
traversal are not configured by this example; tests cover local processes.

Each request uses a fresh authenticated iroh connection. Requests carry sequence
numbers, and the owner retains the last response so a lost join receipt or
rotation response can be retried without applying it twice. Owner messages and
commits form an ordered queue; the member polls, acknowledges deliveries, and
skips already processed events. Up to 16 unacknowledged events are retained.
Connection failures retry the exact request while both processes remain alive.

Restarting either process requires a fresh group and invitation. No epoch,
private MLS state, delivery queue, or receipt is persisted. This is a two-member
example, not a multi-member chat server. Its JSON protocol is example-local.
It requires the repository's local `tmc/mls` replacement.

The original one-process smoke demonstration remains available:

```sh
GOWORK=off go run ./examples/groupchat demo
```

Run the subprocess chat and lost-response regression tests with:

```sh
GOWORK=off go test -race ./examples/groupchat
```
