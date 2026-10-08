# Failure matrix

“Fail closed” means no new signed sponsorship is returned. Existing valid authorizations can still be used until expiry unless the paymaster is paused or the signer is revoked on-chain.

The issuer signs only a durable approved reservation and commits the artifact before returning it. The local E2E submits through a pinned external bundler. The reconciler consumes confirmed EntryPoint evidence or expires unused signed capacity after confirmed scan coverage. The scoped HTTP service checks readiness before creating a request. Signer failures, lost claims, emergency disable, and storage errors return no new artifact. An already committed artifact remains durable; the HTTP issuance endpoint withholds delivery while globally unready. Paymaster pause is a separate on-chain control.

| Condition | API / ledger behavior | Posture |
| --- | --- | --- |
| PostgreSQL unavailable | Return `STORAGE_UNAVAILABLE`; no reservation or approval result. Existing holds remain durable. | Fail closed |
| Signer unavailable | Return `SIGNER_UNAVAILABLE`; clear the owned claim and keep the reservation held for retry during its original validity window. | Fail closed |
| Signer timeout or ambiguous result | Clear the owned claim when possible; preserve the reservation for a retry inside its original validity window. A crash leaves a fenced lease that another worker can take after expiry. | Fail closed |
| Required RPC unavailable/stale/inconsistent | Return `CHAIN_STATE_UNAVAILABLE`; no signature. | Fail closed |
| Bundler unavailable | API may return already issued approval; client submission fails and reservation remains held until safe expiry reconciliation. No replacement signature for changed fields. | Fail closed for new operation substitution |
| Paymaster paused after artifact issuance | EntryPoint validation reverts before execution. The outstanding artifact can work after unpause only while its signed validity and account nonce still permit it. | Fail closed on-chain |
| EntryPoint paymaster deposit insufficient | EntryPoint rejects the operation even when PostgreSQL capacity was reserved. The signed hold remains until outcome reconciliation. | Fail closed on-chain |
| Duplicate client request, same key/body | Admission recovers the original reservation. Issuance returns the same committed artifact by sponsorship ID without another signature. HTTP returns 200 for the recovered artifact. | Fail closed to duplicate charge |
| Duplicate key, changed body | Return `IDEMPOTENCY_CONFLICT`; do not reserve. | Fail closed |
| Concurrent identical request | Unique key serialization yields one reservation. A fenced signing claim allows one current owner; concurrent callers recover the same artifact. | Fail closed to duplicate charge |
| All-chain budget exhausted | Deny `GLOBAL_BUDGET_EXHAUSTED`; audit; no reservation. | Fail closed |
| Per-chain budget exhausted | Deny `CHAIN_BUDGET_EXHAUSTED`; audit; no reservation. | Fail closed |
| Per-sender quota exhausted | Deny `QUOTA_EXHAUSTED`; audit; no reservation. Released and expired requests still count against the daily admission rate ceiling. | Fail closed |
| Policy changes between requests | A same-key retry keeps the original version and policy hash. Issuance requires its original immutable profile or returns `POLICY_VERSION_CONFLICT`; explicit version revocation blocks new artifacts. | Fail closed on mismatch or revocation |
| Unsigned reservation expires | Bounded expiry operation moves `RESERVED -> EXPIRED`, returns held Wei, and retains sender admission count. | Fail closed |
| Crash after reservation before signing | Recovery resumes same reservation or safely releases it; no second hold. | Fail closed |
| Crash after signing before durable artifact | No signature is returned; after lease recovery, retry signs the same canonical digest under the original reservation and validity. | Fail closed |
| Emergency disable during signer latency | The final transaction rechecks the durable emergency row. A returned signature is discarded; no artifact commits. | Fail closed |
| Crash after artifact commit before response | Retry reads and verifies the exact stored artifact; signer is not called again. | Recover committed result |
| Issued authorization passes validity deadline | Record elapsed authorization once, keep the hold until complete canonical scan coverage reaches a confirmed block whose timestamp is strictly later than `validUntil`; then expire unused once if no canonical event exists. | Fail closed to capacity reuse |
| Operation never submitted | Catch up via HTTP after downtime; expire the signed hold only after confirmed chain-time coverage and no canonical event. | Fail closed to uncertain spend |
| Submission response lost after bundler acceptance | Keep `RESERVED`; recover the included operation by expected `userOpHash` and settle exact cost after confirmations. | Fail closed to false release |
| Submitted, outcome unknown and never included | Keep `RESERVED` until finality-covered unused expiry. Bundler status is not settlement evidence. | Fail closed |
| Target call reverts after valid sponsorship | `UserOperationEvent(success=false)` reports positive actual cost; finalized evidence moves the hold to `CONSUMED` and returns unused capacity. | Fail closed to undercount |
| Provisional event orphaned | Retain orphan observation, reset unresolved outcome to `REORGED`, retain hold, and scan the new branch. Reinclusion settles once. | Fail closed |
| Deep reorg or terminal contradiction | Persist anomaly, stop automatic checkpoint/settlement progress, degrade readiness, and require manual reconciliation. Do not rewrite terminal budget history. | Fail closed |
| Actual gas cost exceeds reserved upper bound | Preserve full observed cost, retain hold, persist anomaly, and degrade readiness. | Fail closed |
| Duplicate event or concurrent workers | Unique fork observation identity and checkpoint/reservation locks yield one terminal transition and one spend row. | Fail closed to double accounting |
| Emergency disable API path fails | Paymaster pause is a separate on-chain control; alert and stop API traffic at ingress if available. Already issued signatures remain exposed until pause lands or expiry. | Fail closed for new issuance where control reaches API |
| HTTP readiness prerequisite fails | Return 503 without new admission or signature. Liveness remains available and status reports a bounded unsafe reason when storage is readable. | Fail closed |
| Deep-reorg recovery dry run is unsafe | Report affected blocks, reservations, and terminal conflicts; refuse `-apply`. Retain fork evidence and manual state. | Fail closed |
| Recovery replay does not converge | Retain `MANUAL_INTERVENTION`; no settlement during replay. Operator rechecks RPC and ancestry before another attempt. | Fail closed |
