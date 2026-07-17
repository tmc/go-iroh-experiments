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

Deliberate non-goals for this experiment: freshness/freeze-attack
mitigation (checkpoints carry no timestamp), tile pruning, operator crash
recovery, and admission control. See `doc.go`.
