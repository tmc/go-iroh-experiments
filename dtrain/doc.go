// Package dtrain coordinates distributed training over iroh.
//
// A Group joins a named gossip topic and keeps a deterministic ranked
// membership. The group reports direct gossip neighbor joins and leaves, while
// membership snapshots are ranked by endpoint ID so all peers can make the same
// collective plan.
//
// Groups provide AllReduce, AllGather, rank-0 Broadcast, and Barrier collectives
// for small synchronous training loops and examples.
package dtrain
