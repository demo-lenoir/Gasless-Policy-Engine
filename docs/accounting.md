# Durable admission and accounting

## Admission identity

`Fingerprint` is SHA-256 over a versioned, length-delimited binary encoding of the normalized chain ID, EntryPoint, sender, nonce, complete account execution calldata, decoded target, value, selector, inner calldata hash, all five gas quantities, both fee caps, and the requested lifetime presence/value. Ethereum integers occupy 32 bytes; addresses and selectors use their fixed widths. JSON field order, whitespace, and hex letter case are not identity inputs. Database times and current policy version are excluded. A retry with the same scoped idempotency key and fingerprint returns the original request, decision, and reservation even after policy publication changes. A different fingerprint returns `IDEMPOTENCY_CONFLICT`.

The fingerprint is an off-chain request identity. It is not an EIP-712 digest and does not authorize a UserOperation. One new idempotency key creates at most one logical request. A new key is a new financial request even when the fingerprint matches.

## Economic limits

For an approved v0.9 draft, the held amount is `EstimatedUpperBound = (callGasLimit + verificationGasLimit + preVerificationGas + paymasterVerificationGasLimit + paymasterPostOpGasLimit) * maxFeePerGas`. Checked uint256 arithmetic rejects overflow. It is a conservative policy admission cap, not measured gas expenditure. The static policy checks every component before accounting.

An all-chain UTC daily row and a per-chain UTC daily row hold Wei capacity. All configured chains must declare the same native gas asset as the all-chain cap; this is a configuration assertion, not an RPC-derived fact. A sender row per chain and UTC day has both a Wei cap and an admission count. The count increments once when a reservation commits and is never refunded by release or expiry. The Wei hold is refunded by release or eligible expiry. This distinction prevents repeated reserve/release calls from bypassing the sender rate ceiling. On consumption, the hold moves to actual consumed Wei and the active hold count moves to consumed count; the admission count remains charged. The reservation belongs to its admission day even when it transitions later.

UTC days are half-open intervals `[00:00:00, next 00:00:00)`. Period rows are created as needed, never reset in place. Exact `Now` is supplied by the caller; PostgreSQL does not select the admission day with its own clock. The daily budget remaining metric is a floating-point observation; exact balances live in `budget_periods`.

## Transaction and lock order

Static normalization and policy evaluation happen before the transaction. The principal PostgreSQL transaction resolves or claims `(client_scope, idempotency_key)` under a unique constraint, checks the fingerprint, records `REQUEST_CREATED`, and either records a stable denial or acquires capacity. Static and accounting configuration are published together under a version/hash after address and list-order normalization; reusing a version with different rules or limits fails. For an approved new request, it locks the chain emergency row, then all-chain budget, per-chain budget, and sender quota rows. It checks every limit before updating any counter. Reservation, counters, request decision, and `RESERVATION_APPROVED` audit event commit together. No signer, RPC, or HTTP call occurs inside the transaction.

The same order applies to the budget rows in release, expiry, and consumption. Those operations lock the existing reservation first; admissions create a new reservation and never wait on another reservation row. Two expiration workers use `FOR UPDATE SKIP LOCKED` over a bounded indexed batch. A failed transaction rolls back all counters and audit writes. PostgreSQL `READ COMMITTED` row locks and unique constraints are the concurrency mechanism. Serialization/deadlock retries replay the entire admission transaction at most three times under the caller's deadline, with a metric for retries. Other errors fail closed.

`sponsorship_requests` has one row per key and stores the fingerprint, normalized request payload, and decision. `sponsorship_reservations` has one row per approved request and, after issuance, the immutable authorization fields. Admission publishes `issuance_profiles` in the same transaction as the request; each row binds a policy version and chain to paymaster, EntryPoint, account code hash, and signer identity. `budget_periods` carries global, chain, and sender period balances. `audit_events` is append-only by intended application role and records creation, denial, approval, signing, and terminal transitions. A production role must withhold update/delete privilege on audit rows. Tests use the database owner role in disposable databases; role provisioning remains deployment work.

## Lifecycle

| State change | Accounting effect | Eligibility |
| --- | --- | --- |
| `RESERVED -> CONSUMED` | Remove the hold; add exact EntryPoint `actualGasCost` to consumed Wei; release the unused remainder. | Canonical `UserOperationEvent` at the configured confirmation threshold, or the Phase 2 persistence transition used in storage tests. |
| `RESERVED -> EXPIRED` | Return held Wei; keep the sender admission count. | Unsigned: `validUntil <= supplied Now`. Signed: no canonical event and a confirmed, complete chain-time scan strictly beyond `validUntil`. |
| `RESERVED -> RELEASED` | Return held Wei; keep the sender admission count. | Only while no signed artifact was issued. |

Repeated calls to the same terminal state are idempotent. A different terminal state, or any terminal-to-`RESERVED` attempt, is a state conflict. Transition, original-period budget update, actual-spend row where applicable, and audit append share one transaction. Phase 3's `authorization_expired_at` remains an elapsed-time marker and does not release Wei. The original expiry operation still handles only unsigned rows; the reconciler alone can expire a signed hold with finality-covered absence. See [reconciliation](reconciliation.md).

## Indexes and limits

The unique `(client_scope, idempotency_key)` index serializes duplicate creation. `sponsorship_reservations(request_id)` prevents a second reservation for one request. `budget_periods` has a primary key on scope, day, chain, and subject for the locked point lookup. Partial validity indexes cover unsigned reservation expiry and issued artifact expiry marking in validity order. `issuance_profiles` has one immutable row per policy version and chain. Audit indexes serve request and sponsorship histories. No broad table scan is required for a bounded expiry batch.

Malformed requests that cannot normalize have no derived sender or canonical fingerprint and are rejected before persistence. At the Phase 2 boundary, the service core had no HTTP endpoint or signing path. The current HTTP service returns an approved response only after a signed artifact is durable.
