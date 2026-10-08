# ADR 0003: transactional sponsorship reservations

Status: Accepted; admission, accounting, and signed-artifact settlement implemented.

## Reservation unit and limits

For each approved operation, hold `EstimatedUpperBound` from the five v0.9 prefund gas fields and maximum fee. `PolicyPaymaster` checks the bound cost against EntryPoint's `maxCost`. UTC daily all-chain, per-chain, and per-sender rows each count consumed spend plus unresolved holds. An all-chain raw-Wei cap is valid only for chains configured with the same native gas asset; construction rejects a declared asset mismatch. This identity remains an operator assertion until chain observation is implemented. Per-sender quota has a Wei ceiling and a durable admission count ceiling. PostgreSQL `NUMERIC(78,0)` stores chain amounts exactly. Application arithmetic uses checked uint256 values; metrics are approximate floating-point observations only.

An allowance is available only if all three Wei limits and the sender count limit accommodate the request. The sender admission count increments once per new reservation and remains charged after release or expiry. On confirmed consumption, the hold is removed and the EntryPoint event's actual charge is added to consumed spend; the unused remainder returns to available capacity. A verified on-chain overage is retained in full as an accounting anomaly, with the hold kept and readiness degraded; it is never clipped.

## Transaction protocol

1. Normalize request and calculate canonical request fingerprint. Resolve the candidate policy and external observations before entering the transaction.
2. In one PostgreSQL transaction, resolve or claim `(client_scope, idempotency_key)` under a unique constraint. On existing key, compare fingerprints: same fingerprint returns the stored state; different fingerprint is conflict. A new request checks its immutable published policy/accounting hash and locks the emergency row, all-chain budget row, per-chain budget row, and sender row, in that order.
3. Persist the decision, hold all three Wei amounts, charge the sender admission count, insert the `RESERVED` reservation, and append audit events. Commit. A denied normalized request is also persisted with reason but creates no hold.
4. Build the typed authorization solely from the committed snapshot and reservation. Sign outside the transaction. On a definitive signer rejection, use a new transaction to move `RESERVED -> RELEASED`, return capacity, and append an audit event. A timeout with an unknown signer outcome keeps the hold for recovery. If the release transaction fails, leave the hold in place for recovery.
5. In a second transaction, lock and recheck the chain emergency control, store the exact signed artifact and digest, mark issuance durable, and append an audit event. Return the artifact only after commit. If disable committed first, discard the signer result and release the hold in that transaction. If this transaction fails, do not return the signature; retry/recovery may sign the same reservation again.

The signer call and network response are not inside a database transaction. There is no distributed transaction with the signer, bundler, or chain. `sponsorship_requests`, `sponsorship_reservations`, period counters, and `audit_events` share transaction boundaries for state transitions. An append-only audit ID and unique event identity make retries safe.

## Lifecycle and recovery

| Transition | Evidence and effect |
| --- | --- |
| `RESERVED -> CONSUMED` | Confirmed canonical EntryPoint evidence for the signed operation moves the hold to actual consumed spend; the sender admission count remains charged. |
| `RESERVED -> EXPIRED` | For an issued authorization, a finalized chain scan must cover the whole validity window with no inclusion. Release held Wei but retain the sender admission count. |
| `RESERVED -> RELEASED` | No signature was durably issued and processing was cancelled or definitively failed. Release held Wei but retain the sender admission count. |

If inclusion is unknown, keep `RESERVED` even after wall-clock expiry. Indexer outage, RPC inconsistency, or reorg extends the hold. Recovery may release a pre-issuance failure but cannot infer non-inclusion solely from a timeout. A transaction committed with signed artifact but response lost serves the stored bytes on retry. A crash after signing but before artifact commit retries the same reservation and payload, never creating a new hold. Identical requests serialize on the unique idempotency key and return the same stored admission result.

An operation never submitted, or never included, becomes `EXPIRED` only after finality-covered absence. An operation submitted with unknown outcome remains held. Policy edits after reservation do not change its signed snapshot; emergency disable/pause is separate. A retry with a new idempotency key is a new financial request and may reserve again, so clients must reuse keys for network retries.

## Period and finality rules

The UTC day is assigned at reservation time and remains the charge period even if execution occurs after midnight. Period rows are never reset in place. A new day creates new rows. Later chain reconciliation must define late charges, reorg handling, and finality depth before issued authorizations can be consumed or expired. If a chain lacks a reliable finality signal, no automatic expiry release of issued authorizations is allowed.

A published policy update may lower a period limit under the same row lock. If existing held plus consumed use already exceeds the new limit, no further reservations are accepted; existing signatures remain valid unless the emergency on-chain control is used. An increase is likewise applied under lock and audited. Versioned policy history remains immutable.

PostgreSQL row locks and constraints are the correctness mechanism. Redis is unnecessary for the expected rate and cannot replace the durable transaction. A separate read cache may later improve latency but cannot authorize spending.
