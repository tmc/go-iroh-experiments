# dtrain

`dtrain` provides distributed-training coordination primitives over
go-iroh. A `Group` joins a named gossip topic, ranks members deterministically
by endpoint ID, and uses the ranked membership for collectives.

The module includes:

- gossip-backed group membership with Join, Leave, and Membership events
- stream AllReduce for `Sum`, `Mean`, and `Max`
- rank-0 parameter broadcast
- barrier rendezvous

The AllReduce implementation uses pairwise all-to-all exchanges over iroh
bidirectional streams. For each peer pair, the higher rank dials the lower rank
and both peers exchange vectors on the same stream, so every peer reduces all
contributions locally without a rank-0 gather.

Run the DiLoCo-style example with:

```sh
go test -run '^Example_diloco$'
```

The example starts in-process iroh peers, performs local toy SGD steps on a
small `[]float32` model, averages parameters with AllReduce every outer step,
and checks that all peers converge to identical parameters.
