# Changelog

## 2.6.0

Redis-less journal rewrite, one-round-trip admission, and sustained-load
resilience release. (Supersedes the unpublished 2.5.0.)

- Replaced the SQLite usage spool with a per-process append-only journal
  (WAL). Every completed request costs one appended, group-committed and
  fsynced JSON line — merges included — so journal work per request is O(1)
  regardless of how many requests have merged into an event. The previous
  SQLite journal rewrote the full merged row (with its growing attachment
  list) on every request, which made Redis-less p99 latency climb with
  sustained bursts. SQLite is no longer used anywhere in the SDK.
- Journal recovery uses whole-file adoption: each process owns one journal
  file; a file whose owner stopped writing for `spool_claim_grace` (default
  120s) is claimed atomically by rename, replayed, re-journaled under the
  adopter's ownership, and only then removed, so an adopter crash cannot lose
  events. Graceful shutdown backdates the file for immediate adoption by the
  next process. If another process adopts a live worker's file (clock skew,
  aggressive grace), the owner's next write detects the theft and rebuilds a
  complete journal; duplicates are settled by the server's idempotency
  receipts.
- Rows left behind by a pre-2.5 SQLite spool are migrated automatically on
  startup under the same owner-fenced grace rules and then removed from the
  legacy file. A still-running 2.4 worker keeps its own rows.
- Dead-lettered events are appended to a per-process `*.dead.jsonl` file with
  their full payload.
- Cold-burst event coalescing: concurrent requests for the same API key,
  policy, status and hour now wait for the first in-flight event creation
  and merge into it instead of opening one event per in-flight request.
- Outage resilience: the delivery-failure backoff is now armed inside
  `flush()` itself and is authoritative against every flush trigger - the
  background deadline, the full-batch fast path, and response-bound
  serverless flushes. Previously a full retry backlog satisfied the
  full-batch rule, so each new request re-armed an immediate retry; every
  rapidly failing flush froze the open event at a tiny count and fragmented
  the bounded queue to its 10,000-item limit within minutes of a
  control-plane outage, after which requests were 503'd. Verified at 115k
  requests/second against an unreachable control plane: zero rejections,
  one delivery attempt per interval, and the queue stays at the merge-cap
  minimum.
- The per-event merge cap is now 10,000 requests (decoupled from the
  500-request delivery batch trigger), so the bounded queue holds roughly
  100M requests worth of usage during an outage instead of 5M. Healthy-state
  batching is unchanged.
- The queue-full rejection log is throttled to once per second instead of
  once per rejected request.
- Fixed delivery starvation under sustained concurrency: flush selection
  skipped events with a merge in flight, and at high request rates the open
  event's merge latch was never free at selection time - so flushes
  delivered nothing, re-armed immediately, and hot-looped while the backlog
  grew and requests slowed. Selection now closes the event to new merges,
  settles in-flight increments (bounded wait), then freezes and delivers.
- Long-run journal performance: the group-commit writer no longer builds
  every live event's payload on each batch (previously O(backlog) per
  commit); the journal requests live state only for the rare rebuild or
  compaction. Compaction now triggers on the garbage ratio (file at least
  twice the live state) with a 1 MB floor, so a large live backlog is never
  rewritten per append and the file stays small - sustained throughput is
  flat (measured: 1.5M requests at a constant ~17k records/s, journal
  bounded under 1 MB, file removed on clean shutdown).
- `flush_on_response(only_if_due=True)` now joins one coalesced delivery
  pass instead of looping until the caller's own event ships, which
  serialized every in-flight request onto delivery latency under load; an
  event that misses the pass ships with the next due batch.
- The per-second rate check now rides inside the atomic reservation script
  (memory and Redis, script marker v4): the entire admission decision -
  RPS, quota, balance, platform cap and monetary hold - costs one Redis
  round trip per request instead of two. A rate-limited request consumes no
  quota, balance or platform capacity. Behavior change: RPS enforcement now
  fails closed with the rest of the admission decision when Redis is down
  (previously it briefly failed open on its own).
- A key-verification response can no longer overwrite the snapshot's
  billable status codes: a snapshot refresh completing while the
  verification was in flight would have been silently rolled back to the
  older set, changing billing decisions. The snapshot is now the sole
  authority for billable statuses.
- Fixed `microauth_fastapi.__version__`, which still reported "2.3.0" in the
  published 2.4.0 package.

## 2.4.0

Batching, aggregation and exact-accounting audit release.

- Usage reporting now batches deliveries: a flush happens when 500 requests
  accumulate or `report_interval` (default now 5 seconds) elapses since the
  last flush, whichever comes first. The serverless response-bound flush
  applies the same rule instead of shipping every response individually, so
  one usage call covers up to 500 requests.
- Requests sharing an API key, usage policy, status code and hour bucket now
  merge into one counted usage item (up to 500 per item) with or without
  Redis. A 150-concurrent burst becomes a single wire item, receipt and
  accounting pass on the API instead of 150. Redis merges are O(1) (a counter
  increment plus one appended limiter attachment); once an item has been
  selected for delivery its payload is frozen, because the server's receipt
  pins the idempotency key to an exact count.
- Unified every Redis Lua script marker and the shared snapshot envelope on
  one protocol version (v3). Older SDK versions reject v3 cache entries and
  refresh directly, and vice versa; no compatibility shims are carried.
- `UsageReporter.record()` is now a coroutine; the SQLite journal writes
  moved off the event loop into a single group-committing writer.
- Redis acknowledgements are batched per customer/credential pair, the no-op
  billable finalize round trip is skipped, and reservation-time
  acknowledgement cleanup is bounded, keeping the hot path O(1).
- Hardened every audited failure path for exact accounting: request
  cancellation during finalization releases the queue reservation and the
  monetary hold instead of leaking them; the SQLite journal writer runs as a
  detached task so a cancelled request can never strand other requests'
  writes; Redis merges are idempotent (per-request dedup tokens with one
  retry), so an ambiguous timeout cannot double-count after crash recovery;
  a transient journal failure now heals after a 5-second cooldown instead of
  poisoning the process into permanent 503s; and the shared SQLite journal is
  owner-fenced with lease-style claims, so multi-worker hosts can no longer
  steal a live worker's rows or dead-letter billed usage.
- Performance under high cardinality: limiter acknowledgements and restores
  are pipelined into single Redis round trips, the batch trigger is an O(1)
  counter, a full batch completed during an in-flight flush now delivers
  immediately, event age checks parse timestamps once, dead-lettered Redis
  events retain their full payload for reconciliation, and the invalid-key
  negative cache is hard-capped.

## 2.3.0

Durable delivery and distributed-coordination hardening release.

- Added a Redis-backed durable usage queue with lease-based cross-worker
  delivery. Every completed request's usage event is durably enqueued before
  the final response body is released; a dead worker's leases expire and any
  other worker recovers and delivers its events, keeping accounting
  at-least-once across serverless instance replacement. Requires Redis with
  persistence (managed offerings such as Upstash persist by default;
  self-hosted Redis needs AOF).
- Shutdown with the durable queue hands undelivered claims back to the shared
  queue for other workers instead of raising a drain error.
- Events older than the API's 45-day usage age limit are dead-lettered with
  their reservation released instead of being retried into a guaranteed
  rejection.
- Hardened the shared snapshot cache: cache keys and envelopes are
  credential-scoped, publications carry fencing tokens so an expired refresh
  leader cannot overwrite a newer snapshot, payloads are digest-checked and
  size-bounded, and the origin leader's reservation-reconciliation cutoff is
  preserved through hydration (closing a temporary overspend window).
- Cached snapshots can no longer clear an authoritative 401/403 credential
  rejection, and older cached data can never replace a newer local snapshot.
- Expired usage policies now accept another instance's published snapshot,
  so only one leader reaches the control plane at policy expiry.
- Frozen serverless workers recover on-request: a stale snapshot triggers a
  throttled inline refresh from the shared cache before rejecting traffic.
- Snapshot cache waiters poll with jittered exponential backoff instead of a
  fixed 50 ms interval.

## 2.2.1

- Journal serverless usage before the final response frame, then deliver it
  after that frame is sent so control-plane accounting does not delay callers.
- Coalesce concurrently completed responses through a short post-response
  microbatch window, avoiding one usage request per application request during
  serverless concurrency bursts.
- Release the billable monetary reservation when journaling a usage event
  fails, instead of leaking reserved credit until the reservation TTL.
- Document the serverless background-execution and durable-filesystem
  requirements explicitly.

## 2.2.0

Serverless caching and reporting reliability release.

- Added a Redis-backed shared snapshot cache. Cold starts now reuse validated
  snapshots, and a distributed refresh lock prevents autoscaling workers from
  stampeding the snapshot endpoint.
- Made `report_interval` an oldest-pending-item deadline driven by an explicit
  wake-up signal instead of a blind periodic sleep.
- Added automatic response-bound usage flushing on Vercel and AWS Lambda so a
  frozen event loop cannot strand the final request until another invocation.
  This can be overridden with `flush_on_response`.
- Added `flush_usage()` for explicit drains in jobs, tests, and custom
  serverless lifecycle integrations.
- Added concurrency and timing regressions for shared cold starts, timer-only
  delivery, response-bound delivery, and arrivals during an active flush.

## 2.1.0

Production reliability release.

- Added durable, bounded usage delivery with stable per-item idempotency
  keys, exact response status reporting, partial acknowledgement handling and
  explicit shutdown-drain failures.
- Added strict snapshot and usage validation for statuses, timestamps and
  JSON-safe integer ranges.
- Added an absolute stale-snapshot ceiling.
- Added immutable usage-policy IDs to queued events so delayed reports keep
  the pricing and quota rules that authorized the request. Expired policies
  are refreshed before new requests are served.
- Added authoritative platform monthly allowance parsing and proactive hard
  cap enforcement. Redis coordinates the cap exactly across workers; memory
  enforcement remains explicitly process-local.
- Made Redis RPS checks atomic and scoped them to each customer and API
  credential pair.
- Added dependency injection for externally owned HTTP and Redis clients.
  The SDK closes only clients it creates.
- Added exported typed errors for configuration, malformed responses, usage
  acknowledgements, queue capacity, durable spool, shared limit backend and
  shutdown drain failures.
- Raised the FastAPI and HTTPX minimums to versions whose supported dependency
  trees contain the current Starlette and h11 security fixes.
- Kept the existing `MicroAuth(app)` dependency and OpenAPI security scheme.

The coordinated MicroAuth API must include `generated_at` and
the flat `platform_monthly_*` allowance fields in snapshots. Each customer
also includes `usage_policy_id` and `policy_valid_until`. Usage requests use
`idempotency_key`, `api_key_id`, `usage_policy_id`, `status_code`, `count` and
`period_start`; responses return one status in `results` for every submitted
idempotency key. See the README for the exact JSON contract.
