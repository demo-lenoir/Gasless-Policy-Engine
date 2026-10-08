# Observability contract

## Metrics

Prometheus metrics use fixed decision and reason enumerations only. Chain labels are an operator-configured bounded set. Never label with sender, target, transaction hash, sponsorship ID, digest, idempotency key, or request ID.

| Metric | Type | Labels / meaning |
| --- | --- | --- |
| `gasless_requests_total{decision,reason}` | Counter | Approved, denied, pending, error; stable bounded reason code. |
| `gasless_policy_eval_seconds` | Histogram | Pure evaluation duration, bounded chain label optional. |
| `gasless_sponsorships_reserved` | Gauge | Outstanding `RESERVED` count. |
| `gasless_sponsorships_expired_total` | Counter | Confirmed expiry transitions. |
| `gasless_estimated_spend_wei` | Gauge | Sum of admitted upper bounds; includes terminal reservations after refresh. Numeric samples lose large-integer precision. |
| `gasless_actual_spend_wei` | Gauge | Finalized actual gas cost refreshed from PostgreSQL; floating-point sample is approximate. |
| `gasless_budget_released_wei` | Gauge | Returned held capacity refreshed from PostgreSQL. |
| `gasless_sponsorships_consumed_total` | Counter | Committed finalized consumption observed by this process. |
| `gasless_reconciliation_events_total{result}` | Counter | Bounded committed settlement result. |
| `gasless_reorgs_total` | Counter | Canonical branch changes processed by this watcher. |
| `gasless_reconciliation_lag_blocks` | Gauge | Observed head minus durable scanned checkpoint. |
| `gasless_daily_budget_remaining_wei` | Gauge | Published all-chain limit less consumed and held for the observed UTC day; it may be negative after a limit reduction. |
| `gasless_paymaster_balance_wei` | Gauge | EntryPoint deposit observed at referenced block. |
| `gasless_signer_errors_total` | Counter | Bounded error class such as timeout/unavailable/invalid_response. |
| `gasless_db_transaction_retries_total` | Counter | Bounded full admission retries for serialization/deadlock SQL states. |
| `gasless_signing_total{result,reason}` | Counter | Bounded issuance outcomes. |
| `gasless_signing_seconds` | Histogram | Issuance duration including signer latency. |
| `gasless_artifacts_active` | Gauge | Issued reservations still inside their validity window; refresh from PostgreSQL. |

Prometheus uses floating-point samples; wei gauges can lose integer precision. Financial decisions and reports read exact database integers. Histograms and traces may carry a sampled request ID; metric labels may not.

Phase 2 implements requests, policy duration, active reservations, expiration count, estimated spend, daily all-chain remaining, and transaction retries. Phase 3 adds bounded signing outcomes, signer error classes, issuance duration, and active artifact count. Phase 5 adds committed consumption, actual spend, released capacity, reconciliation result, reorg, and lag observations. Phase 6 observes the EntryPoint paymaster deposit through `balanceOf(paymaster)`. The service calls `RefreshFromLedger` at startup and after watcher cycles to restore gauges from PostgreSQL. Counters are process-local observations and reset with the process. The remaining gauge reflects the last committed period observed; it is not an accounting source.

## Audit and traces

Every decision and state transition appends an immutable audit event with event ID, occurred time, request/correlation ID, sponsorship ID when assigned, policy version, chain ID, EntryPoint, paymaster, sender, target, selector, decision, stable reason, typed digest when built, expiry, reservation cap in wei, old/new state, and referenced block/hash for external observations. Store only necessary calldata hashes, never raw secret material. Redact account and paymaster signatures from routine logs. A retention/access policy is required before real deployment.

OpenTelemetry spans cover HTTP, policy evaluation, admission transaction, signer handoff, RPC scanning, and settlement transaction. Set `OTEL_EXPORTER_OTLP_ENDPOINT` or `OTEL_EXPORTER_OTLP_TRACES_ENDPOINT` to enable OTLP/HTTP export; otherwise the tracer is inert. Span names contain stable operation classes without raw calldata, signatures, addresses, or key material. Export failures do not alter authorization decisions.
