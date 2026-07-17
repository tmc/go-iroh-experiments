# tlogiroh

`tlogiroh` is a distributed transparency log over go-iroh: an append-only,
publicly verifiable log of opaque records, distributed without a central
operator having to stay online.

All Merkle tree, proof, and signature machinery is Go's checksum-database
stack (`golang.org/x/mod/sumdb/tlog` and `sumdb/note`); this module is the
iroh glue:

- hash tiles (standard sumdb tile layout, height 8) and log entries are
  content-addressed iroh blobs, so any peer can mirror the tree
- a single-writer iroh doc maps tile paths, entry indexes, and checkpoint
  sizes to blob hashes — the doc is the index
- signed checkpoints (C2SP format: origin, size, root hash) are broadcast
  on a per-log gossip topic
- witnesses verify consistency and countersign checkpoints by re-signing
  the note; a client requires the operator signature plus K of N known
  witness cosignatures
- clients refuse rollback, verify consistency proofs from their stored
  head, and turn split views into verifiable `Equivocation` proofs that
  are flooded over gossip

The roles are `Operator` (append, publish, announce), `Client` (sync,
update, entry lookup, watch), and `Witness` (cosign, run). Reads go through
a `Source`: a synced doc replica plus a `BlobGetter` (local store or a peer
dialed over the iroh blobs protocol).

Run the full networked flow — operator, witness, K=1 client, and an
injected split view caught as an equivocation — with:

```sh
go test -run TestNetworkCosignEquivocation -v
```

## cmd/tlog-iroh

The `tlog-iroh` command runs the roles as real processes. `tlog-iroh demo`
plays the whole flow in one process on loopback, including the equivocating
twin. For separate processes:

```sh
# terminal 1: serve a log; type entries, one per line
tlog-iroh operator -origin example.org/log

# terminal 2: cosign announcements (paste the ticket and key it printed)
tlog-iroh witness -ticket <ticket> -operator-key <vkey>

# terminal 3: verify with a 1-of-1 witness policy, persisting the head
tlog-iroh watch -ticket <ticket> -operator-key <vkey> \
    -witness-key <witness-vkey> -head head.note

# fetch entry 1, verifying its inclusion proof against the saved head
tlog-iroh get -ticket <ticket> -operator-key <vkey> \
    -witness-key <witness-vkey> -head head.note -index 1
```

Deterministic checkpoints re-announce as byte-identical gossip messages,
which iroh-gossip deduplicates: each peer sees a given checkpoint once. A
reader whose doc replica has not yet caught up therefore parks the
checkpoint and retries as the replica syncs (`Watch` and `Run` do this
internally).

Deliberate non-goals for this experiment: freshness/freeze-attack
mitigation (checkpoints carry no timestamp), tile pruning, operator crash
recovery, and admission control. See `doc.go`.
