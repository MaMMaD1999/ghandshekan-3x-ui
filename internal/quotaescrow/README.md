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
