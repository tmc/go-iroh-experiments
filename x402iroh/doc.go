// Package x402iroh runs x402-paid HTTP services over iroh.
//
// The resource server, the paying client, and the facilitator are all iroh
// endpoints: HTTP/1.1 requests travel over bidirectional iroh streams
// (ALPN "x402/iroh/1"), and payments on the "iroh:ed25519" network are
// authorized with the same ed25519 keys that identify the endpoints. No
// TLS, DNS, or blockchain is involved; iroh authenticates and encrypts the
// transport, and a [Ledger] facilitator settles payments by moving credit
// between endpoint accounts.
//
// The payment scheme is "exact", mirroring the EVM exact scheme's payload
// shape (a signed transfer authorization with a validity window and a
// replay nonce) with iroh endpoint IDs in place of wallet addresses.
package x402iroh
