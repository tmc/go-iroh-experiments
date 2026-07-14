# directpath

`directpath` is a small direct-path probe for go-iroh experiments. It does not
use relays and reports the QUIC path selected for an iroh connection.

Use it to separate three cases:

- the peer has no usable direct address candidate;
- a bind family/address cannot receive inbound UDP;
- the connection succeeds but selects an unexpected path.

## Inspect local candidates

```sh
go run ./cmd/directpath-probe inspect
```

The output lists interface addresses and marks IPv4, IPv6, loopback,
link-local, and Tailscale-style candidates.

## Two-host direct echo

On the receiving host:

```sh
go run ./cmd/directpath-probe listen -bind :0
```

Copy the printed `id` and `addr` fields. On the dialing host:

```sh
go run ./cmd/directpath-probe dial -peer-id <id> -peer-ip <addr> -n 1048576
```

`dial` prints local/remote socket addresses, connection statistics, and each
known path with `selected`, `validated`, `relayed`, address, RTT, and bytes.
For a direct-path proof, the selected path should be `validated=true` and
`relayed=false`.

On macOS firewall-gated hosts, use this as the minimal reproduction: if the
listener prints a reachable Tailscale address but `dial` times out before the
listener logs an accepted connection, inbound UDP is being dropped before
go-iroh can validate a path.

## Two-host direct-path upgrade with relay coordination

`twobox-directpath` is the relay-enabled complement to the probe: the client
dials with relay coordination available, so it checks that a connection
upgrades to a validated direct path even when a relay fallback exists, and it
measures stream throughput on the selected path.

On the receiving host:

```sh
go run ./cmd/twobox-directpath -mode server -bind <host>:0
```

Copy the printed endpoint id and address. On the dialing host:

```sh
go run ./cmd/twobox-directpath -mode client -id <id> -peer <host:port> -bytes 2500000
```

The client reports each path with selected/validated/relayed flags and the
achieved throughput. Pass `-relay=false` to forbid the relay fallback
entirely, which turns it into a stricter version of the probe's `dial`.
