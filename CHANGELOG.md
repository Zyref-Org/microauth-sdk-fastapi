# Changelog

## 2.3.0

Durable delivery and distributed-coordination hardening release.

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
- `UsageReporter.record()` is now a coroutine; the SQLite journal writes
  moved off the event loop into a single group-committing writer.
- Redis acknowledgements are batched per customer/credential pair, the no-op
  billable finalize round trip is skipped, and reservation-time
  acknowledgement cleanup is bounded, keeping the hot path O(1).
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
