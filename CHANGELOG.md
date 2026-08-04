# Changelog

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
