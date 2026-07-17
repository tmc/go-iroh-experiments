# x402iroh

`x402iroh` runs [x402](https://github.com/coinbase/x402)-paid HTTP services
over iroh. The resource server, the paying client, and the facilitator are
all iroh endpoints: HTTP/1.1 travels over bidirectional iroh streams (ALPN
`x402/iroh/1`), and payments on the `iroh:ed25519` network are authorized
with the same ed25519 keys that identify the endpoints. No TLS, DNS, or
blockchain — iroh authenticates and encrypts the transport, and an
in-memory `Ledger` facilitator settles payments by moving credit between
endpoint accounts.

The x402 protocol layer (wire types, 402 challenges, payment headers,
facilitator REST API) comes from [github.com/tmc/x402](https://github.com/tmc/x402);
this module contributes the iroh transport, the `exact` scheme on
`iroh:ed25519` (EIP-3009-shaped authorizations signed by endpoint keys),
the `Wallet` payer, and the `Ledger` facilitator.

```sh
go get github.com/tmc/go-iroh-experiments/x402iroh
```

## Demo

One process, three loopback peers:

```sh
go run ./cmd/x402-iroh demo
```

The client pays 5 credits per request from a 12-credit faucet balance: two
requests succeed with settlement receipts, the third is refused with a 402
challenge (`insufficient_funds`).

Separate processes:

```sh
x402-iroh facilitator -faucet 100
x402-iroh serve -facilitator <ticket> -price 5
x402-iroh get -server <ticket> -path /premium
```

See the [package docs](https://pkg.go.dev/github.com/tmc/go-iroh-experiments/x402iroh)
for the API.
