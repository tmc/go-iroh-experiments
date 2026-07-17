// Package tlogiroh implements a distributed transparency log over iroh.
//
// The log is an RFC 6962 append-only Merkle tree built from
// [golang.org/x/mod/sumdb/tlog], with tree heads signed as
// [golang.org/x/mod/sumdb/note] notes. iroh provides transport and storage:
// Merkle hash tiles (standard sumdb tile layout, height 8) and log entries
// are content-addressed iroh blobs, a single-writer iroh doc maps tile
// paths, entry indexes, and checkpoint sizes to blob hashes, and new
// checkpoints are broadcast on a gossip topic where witnesses countersign
// them. A client accepts a checkpoint only when it carries the operator
// signature and at least K known witness cosignatures, refuses rollback,
// verifies consistency proofs from its stored head, and can prove and flood
// equivocation (two signed checkpoints of the same size with different
// hashes).
//
// A log is named by an origin string (the first line of its checkpoints),
// conventionally the operator's note key name. Log and witness identities
// are note keys ([note.Signer], [note.Verifier]); iroh endpoint keys
// identify transport peers and are orthogonal.
//
// Checkpoints use the C2SP checkpoint format: origin line, decimal tree
// size, base64 root hash. Unlike the sumdb layout, there are no data tiles:
// each entry is its own content-addressed blob whose leaf hash is
// [tlog.RecordHash] of the entry.
//
// The doc timeline uses three key forms, all written by the operator:
//
//	tile/<coord>.w/<www>  hash tile blob: the sumdb coordinate path of the
//	                      complete tile plus the zero-padded actual width
//	entry/<index>         entry blob, index as 20 decimal digits
//	checkpoint/<size>     signed checkpoint note blob, size as 20 digits
//
// Timeline keys are prefix-free by construction: iroh-docs inserts delete
// older entries whose keys extend the new key, so no key may be a prefix
// of another. The explicit tile width suffix exists for this reason.
//
// Checkpoints carry no timestamp and note signatures are deterministic, so
// republishing an unchanged tree yields a byte-identical message. Freshness
// ("freeze attack") mitigation is out of scope for this experiment, as are
// tile pruning, operator crash recovery, and admission control.
package tlogiroh
