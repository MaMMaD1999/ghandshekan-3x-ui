# Quota escrow — staged, not a live panel capability

This package is not connected to the production traffic limiter or node API.
Do not advertise autonomous quota enforcement based on the presence of these
files, the panel version, or the existing custom-accounting capability.

The ledger separates transferred spending rights from actual billed traffic.
Only actual cumulative usage enters `Used`; `Billed` never includes transferred
rights. Signed, per-owner cumulative rows make duplicate and reordered network
reports idempotent. A missing node's remaining grant stays reserved, not charged
and not reassigned to a second node. `Observe` preserves real metering overrun
and deducts that debt from subsequently received credit before new traffic can
be authorized. Coefficients must be applied exactly once by the existing meter.

`Store` persists updates before returning a transfer, uses a transactional
revision check, rejects implicit meter rollback, and refuses to replace a live
policy with a new epoch. SQLite durability requires WAL and synchronous FULL;
the production database adapter must retain those durability guarantees.

Required integration before enabling this on any existing subscription:

- Authenticate policies, scope peer access, pin member identities and provision
  direct peer connectivity without exposing panel administrator credentials.
- Map every device/email alias to the same subscription policy. Include local
  master traffic; exclude mirrored origin counters from local consumption.
- Seed the ledger from committed lifetime counters and existing consumption,
  so activating the feature never rebills old traffic or restores used credit.
- Serialize runtime admission with durable credit state. On exhaustion, apply
  a local temporary runtime block, not a global permanent client-disable flag.
  Reconcile blocks before serving traffic after a process restart.
- Gossip signed rows independently of the master, settle real observations
  even after expiration, and enforce expiry using a checked clock. Poll-based
  counters do not provide a byte-exact cutoff; test and bound runtime overrun.
- Implement fenced renewal/reset/membership transitions. Restoring an old DB
  backup or replacing a lost node must not reissue its previous unspent rights.
  Do not infer failure or reclaim rights solely from a timeout.
- Keep raw/billed usage cards and the application's accounting pipeline on
  actual usage. Escrow transfers must never enter their usage deltas.
- Preserve the legacy and official-panel adapters. Unsupported peers cannot
  be silently counted as members with autonomous enforcement.

Validation so far covers partitions, duplicate/stale/reordered snapshots,
wrong epochs, signature tampering, concurrent owner sequence conflicts,
unused reservations, real polling overrun, SQLite reopen, failed commits,
concurrent transfers, and refusing an unfenced epoch overwrite. These are
component tests, not an end-to-end network-disconnection acceptance test.

Run `go test ./internal/quotaescrow`. SQLite tests additionally require CGO.

Transport components added on 2026-11-03 (still not mounted in production):

- `SyncTransport` retries direct connectivity on every cycle, then bounded peer
  relays, then the explicitly supplied accounting egress. Configuring the
  `accounting-sync` bridge does not make it the preferred transport.
- `SignedExchange` binds the destination, subscription, epoch and random request
  nonce. The destination signs a receipt only after durable merge. A relay cannot
  substitute its own acknowledgement; a previous receipt cannot acknowledge a
  new attempt. Repeated cumulative reports do not bill usage again.
- `HTTPExchange` implements HTTPS delivery and one intermediary, using only
  provisioned peer addresses, bounded bodies and no redirects. This supports the
  Iran -> Austria -> Netherlands example; arbitrary multi-hop discovery is not
  implemented. The production adapter must add peer provisioning, admission
  limits, scheduling and TLS trust configuration before mounting the handler.
- The reserved loopback SOCKS bridge is injected only for an explicit valid
  routing rule. An accounting-only rejection rule follows administrator rules
  so unmatched conditional rules cannot leak into the default outbound. Other
  inbound rules retain their order. Exhausted reserved ports disable the bridge.

TLS integration tests exercise relay delivery between independent SQLite stores,
duplicate reports, new-request receipt binding, failed disk commits, redirected
endpoints and oversized messages. These do not validate production traffic
admission, migration of existing subscriptions, or independent quota enforcement.

Activation/meter components added subsequently:

- `Policy.AlreadyBilled` seeds committed pre-mesh consumption once globally;
  spending grants are limited to the remaining quota, including users already
  above quota. It must come from the authoritative committed subscription total.
- `Store.Activate` persists policy and local source watermarks atomically.
  `ObserveMeter` commits each source's watermark and signed usage in one
  transaction, aggregating multiple device aliases into one owner's usage.
  A retry, restart or failed watermark write cannot double-charge the sample.
  Source counters must be durable local billed counters, not mirrored totals or
  reset-on-read Xray counters. A counter reset is rejected pending a fenced
  lifecycle transition; it never implicitly grants new credit.
- `Admission` reads local durable allowance and expiry without master access.
  This is a decision API, not an installed Xray traffic limiter. The production
  runtime adapter must enforce it and handle errors before this feature is live.
