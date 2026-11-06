# Quota escrow — staged, not a live panel capability

This branch includes local meter and admission adapters, but the complete
runtime limiter, authenticated enrollment and node API are not installed.
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

Peer-cycle components:

- `SyncSubscription` contacts all authenticated members with bounded concurrency,
  so an offline master does not serialize exchanges between healthy nodes. It
  reloads committed rows for each destination and never reallocates grants on
  network failure. `RunSync` runs non-overlapping cycles with cancellable waits.
- A three-store HTTPS test disconnects the master, exchanges actual usage
  between the other two nodes, retries it, and reconnects the master without
  increasing the billed total. Expiry decisions still work while disconnected.
  This remains a component-level test; no production runtime limiter is mounted.

Local accounting and lifecycle adapters added on 2026-11-03:

- `mesh_local_usage` persists local billed deltas in the same transaction as
  ordinary traffic. It excludes imported/global node counters and survives
  subscription resets. Its generation never silently changes on enrollment.
- `ActivateMeshMeters` commits explicit alias bindings, policy and local meter
  baselines atomically. Re-enrollment or a conflicting alias rolls back; neither
  operation can reset an existing ledger. It still requires an authenticated,
  runtime-fenced caller; it is not exposed to browsers or peers.
- `SettleMeshMeters` settles every local alias of a subscription transactionally.
  Retry/disk-failure tests preserve usage exactly once. A caller must close
  admission on settlement errors; the periodic runtime caller is still missing.
- The cold Xray configuration and hot local AddUser/AddInbound paths filter
  locally exhausted/frozen enrolled aliases. Unenrolled clients retain their
  legacy behavior. These guards do NOT terminate already-open streams.
- `BeginTransition` persists an admission barrier before draining. `Freeze`
  seals final signed usage only after that barrier. Transfers stop while paused,
  but final local meter settlement remains possible until sealing. Restart,
  duplicate transition, missing-member, wrong-epoch and failed-commit tests pass.
- `CommitTransition` requires every old member's signed final proof, preserves
  actual consumption on renewal and clears it only on an explicit reset. An
  acknowledged-commit retry cannot reset new usage or meter watermarks.
- All five new tables participate in both normal schema migration and SQLite
  to PostgreSQL migration. Runtime capability responses intentionally do not
  advertise autonomous mesh enforcement.

Deployment blockers remain: authenticated member/policy provisioning and TLS
trust, safe live-session cutoff, supervised metering/gossip workers, distributed
reset/renewal integration, checked-clock handling, and end-to-end partition
acceptance tests with real traffic. Do not enroll live subscriptions or label
this branch a completed mesh release until those checks pass.

Runtime gate work on 2026-11-06 (not yet installed on production):

- Custom core commit `4a19ecd0` adds explicit per-user runtime gates. A gate
  closes existing inbound sockets and pipe endpoints, rather than relying on
  credential removal. Ordinary RemoveUser behavior remains unchanged.
- Core instance IDs and monotonically increasing revisions reject old-controller
  unblock requests and conflicting retries. Registration and blocking are
  serialized; a connection cannot escape between its admission check and tracking.
- `XrayAPI.ReconcileUserGates` uses a separate protobuf wire contract, so the
  panel's ordinary upstream core dependency and legacy adapters remain unchanged.
- Core statistics/dispatcher tests pass with the Linux race detector. The panel
  client passed an RPC compatibility test against the custom core's generated
  server. A three-core VLESS/TCP test demonstrated closing an existing stream,
  denying a new request, preserving an unrelated user's traffic, and reconnecting
  after removing the local gate. The close deadline is shorter than the HTTP
  client's own timeout, so that timeout cannot make the assertion pass.
- This establishes the TCP runtime primitive, not complete mesh enforcement.
  Supervised settlement/gossip, authenticated enrollment, lifecycle orchestration,
  checked clocks/restore protection and other protocol paths still need integration
  and acceptance testing before live enrollment.

The integration tests use `-tags meshcore`, a temporary Go module replacement
pointing at the custom core, and `MESH_TEST_CORE` pointing at its test executable.
They use isolated loopback listeners and do not contact production inbounds.

Automatic quota cutoff acceptance on 2026-11-06:

- Core `4de8fd8a` keeps mesh and ordinary configuration fences independent;
  clearing one cannot reopen a user denied by the other.
- The traffic job now reconciles disabled users even when whole-core restart on
  disable is switched off. A custom core closes their existing sockets; legacy
  cores retain their existing configured restart policy. A node-sync-authorized
  reconcile endpoint carries this behavior to updated remote nodes.
- Real VLESS, VMess and Trojan streams, with and without Mux, passed three runs
  of cutoff, new-connection denial, unrelated-user survival and re-enable tests.
- `TestAutomaticQuotaCutoffWithoutRestart` starts a real panel and core, with
  restart-on-disable off, and waits for the scheduled quota job (no direct test
  gate command). Both volume exhaustion and expiry cut the ongoing download;
  the core instance stays unchanged and another user's open download continues.
- Quota detection still follows the traffic polling interval; these tests do
  not claim a zero-byte overrun or coverage of the Psiphon application itself.
- Full web/service/runtime/controller/job, xray and escrow regression tests pass.
  None of this evidence means that mesh provisioning or production rollout is
  complete; the deployment blockers above still apply.

`service.MeshEnforcer` now joins durable settlement and runtime deny decisions
in a serialized local cycle. A per-subscription settlement failure fences that
subscription only; a global DB failure retains fences for all known aliases.
Deleted bindings never implicitly reopen an alias. Tests cover retry without
double billing, exhausted allowance, expiry, missing keys, unreadable bindings
and an unconfirmed core fence. This adapter still requires the authenticated
enrollment, checked-clock and supervised runtime integration described above.

The checked-clock component now persists a time floor, refuses a missing clock
record during normal runtime, and rejects a backward clock on process restart.
Its tests cover small clock corrections, restart rollback and failed disk writes.
This is not a replacement for an external restore checkpoint. Cold configuration
and hot admission now use the checked clock for enrolled aliases; ordinary
unenrolled clients retain their behavior. Enrollment initializes the floor in
its transaction, and `MeshEnforcer.ReconcileCurrent` uses it for local decisions.
The production mesh supervisor is still pending.

Enrollment authorization now signs the complete policy, node identities and
alias mapping with a separately pinned authority key. Validity is limited to
15 minutes. Tests reject changed aliases/quotas, wrong node identities, stale
envelopes, shared node keys and reusing a usage key as the enrollment authority.
The endpoint/orchestrator must still validate authoritative clients and drain
runtime sessions before committing `ActivateMeshMeters`; a verified signature
alone does not authorize skipping that barrier.

The supervisor component runs local enforcement separately from network exchange
and waits for both workers on cancellation. An unconfirmed runtime fence or a
worker panic invokes a synchronous emergency-stop callback; an already-fenced
settlement failure or ordinary peer outage does not stop unrelated users.
Race-detector tests passed three repetitions for blocked network exchanges,
continued local cycles, cancellation and fatal-fence/panic handling. This is
still a component awaiting production configuration and lifecycle wiring.

The mesh HTTP-client factory ignores general proxy environment variables,
requires verified explicit TLS trust, and exposes the accounting-sync SOCKS
bridge only as a separate client restricted to loopback ports 62780–62789.
Tests verify direct HTTPS still works with an invalid general HTTPS proxy and
reject unrelated proxy endpoints and disabled certificate verification. The
exchange supervisor must request that client only in the third-path callback.

Runtime integration verified on 2026-11-07 (release 3.10.2-ghandshekan.34):

- Private identity configuration validates independent enrollment authority and
  node keys, certificate identity, mutual TLS trust, and fixed peer endpoints.
- Panel lifecycle now starts a bounded exchange listener and independent local
  enforcement and exchange workers. Direct traffic is attempted first, peer
  relay second, and the accounting-sync SOCKS route only as the third fallback.
- Cold core configuration excludes enrolled aliases until the gate API confirms
  the current local allowance. Shutdown fences enrolled sessions before workers
  disappear; ordinary unenrolled clients retain their existing behavior.
- Real panel/core acceptance passed three repetitions with an unreachable master:
  a running download stops when its local allowance is exhausted, an unrelated
  user's download survives, and the core instance remains unchanged. Receiving
  a signed credit transfer restores admission without billing the transfer.
- Service, web, job and ledger regression tests pass. The quota/expiry scheduled
  cutoff test also passes against this static Linux build.

This supersedes the earlier notes about pending runtime wiring, not the remaining
rollout requirements. Live enrollment, subscription lifecycle orchestration,
restore checkpoints and multi-node partition acceptance still require completion.
The release does not automatically enroll existing subscriptions.

Restore checkpoint integration tested on 2026-11-07 (not yet enabled in production):

- A separately stored, node-signed SQLite checkpoint records enrolled bindings,
  signed usage/transfer rows, local meters, settlement watermarks and the clock
  floor. Subscription IDs are namespaced separately from checkpoint metadata.
- Higher revision numbers cannot hide regressed signed counters. Epoch changes
  need the old members' signed freeze archive; renewal retains actual usage and
  reset starts a new cycle without rebilling existing lifetime meters.
- Startup checks the checkpoint before core admission, including a panel backup
  that predates enrollment entirely. A restore fault also prevents automatic
  core restart. The enforcer validates before settlement and before admission;
  peer traffic cannot publish a receipt until its checkpoint is committed.
- Tests cover missing bindings/meters/checkpoints, clock and watermark rollback,
  modified signatures, reset/renewal replay and a failed checkpoint write before
  publication. Service/job/ledger regressions passed, and the real offline-master
  stream-cutoff acceptance passed with this checkpoint wired into the runtime.
- Restoring an entire host, including both databases and its signing identity,
  still requires explicit reconciliation/fencing against surviving peers. The
  checkpoint is protection against panel DB rollback, not a hardware counter.

Secure live enrollment/lifecycle orchestration and multi-node rollout acceptance
remain required before advertising the mesh capability or enrolling subscribers.
