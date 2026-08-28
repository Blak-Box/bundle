# `lan/` — the box ↔ desktop surface, as a contract

The receiver's HTTP surface has lived in three places at once: the routes in
`airlock/receiver/server.go`, a hand-mirrored copy in the comments of
`exporter/boxclient/boxclient.go` ("The receiver's wire contract for POST /v1/bundle …"),
and prose in the programme. Three copies of one contract, none of them machine-readable, in a
system whose central claim is that you can verify what it does.

`openapi.yaml` is the single description. It is **public on purpose**: the contract is part of the
trust story, and a customer's auditor should be able to read what the box accepts without being
given the box's source.

## What this file is, and is not

It **documents what the receiver serves today**. It is not a design for a surface that does not
exist. Notably `/v1/app/*` — the single mTLS front door the desktop app will use — **is not in
here, because it is not built.** Speccing it here would put a contract in a public repo for
behaviour nothing implements, which is the failure this repo exists to avoid.

## Verifying it against the implementation

The spec is only worth having if it cannot drift from the server. `lan/openapi_test.go` in the
appliance's receiver module is the intended home for that check — it should assert that every
route in `server.go`'s mux appears here and vice versa. Until that lands, this file is
documentation, not a guarantee, and it says so rather than implying otherwise.
