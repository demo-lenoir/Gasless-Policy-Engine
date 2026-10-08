# Threat model

## Assets

Sponsor/paymaster EntryPoint balance; signer key and key access policy; sponsorship authorization and its validity window; global budget and per-sender quota state; append-only audit log; published policy configuration; EntryPoint, account, and paymaster contract state; chain observations used to make decisions.

## Trust boundaries

The client-to-API boundary carries hostile operation bytes. The API-to-PostgreSQL boundary controls financial holds and durable audit state. The API-to-signer boundary permits a cryptographic act but grants no policy authority to the signer. The API-to-RPC boundary carries fallible chain observations. The bundler-to-EntryPoint boundary carries untrusted submissions. The EntryPoint-to-paymaster boundary is restricted to the configured EntryPoint. The operator-to-policy/paymaster boundary can change future decisions or pause outstanding approvals. See [architecture](architecture.md) for component obligations.

## Actors

Legitimate client; malicious client; party with a compromised frontend or API credential; malicious or stale bundler; faulty or lagging RPC provider; compromised signer infrastructure; operator or administrator, including mistaken or malicious actions.

## Attack and abuse cases

| Case | Control | Residual risk and verification evidence |
| --- | --- | --- |
| Replay of identical sponsorship | Full nonce binding; EntryPoint nonce consumed once; short validity | Reorg may reopen nonce before finality. Solidity replay test and E2E replay rejection. |
| Cross-chain/paymaster/EntryPoint replay | EIP-712 chain and paymaster domain; signed EntryPoint field | Chain fork with same ID and identical deployment needs separate operational controls. Domain mutation tests. |
| Calldata or target substitution | Signed outer `callData` hash and decoded target/inner hash; on-chain canonical single-call parser and sender code-hash check | Allowed target may route onward; account implementation must remain fixed. Mutation tests and ABI parser fuzzing. |
| Selector abuse or unsupported target | Policy target/selector allowlist; on-chain commitment to approved bytes | Compromised policy or signer can approve bad call. Policy table tests and paymaster mutation tests. |
| Gas inflation or fee escalation | Per-field bounds; reserved cost cap; paymaster `maxCost` check | Fee environment can prevent inclusion. Boundary and cost parity tests. |
| Sender quota or all-chain/per-chain budget race | PostgreSQL period row locks in one order and unique reservation; hold before any later signing | DB compromise can corrupt ledger. Phase 2 runs repeated 100-way race tests against PostgreSQL under the race detector. |
| Arbitrary-message signer abuse | No client digest endpoint; server-owned typed payload; signer service ACL | Compromised API can still ask signer for valid-looking payloads. Interface and authorization tests. |
| Signer unavailable or timeout | Fail closed; hold released only by durable transition | Temporary held capacity reduces availability. Failure injection tests. |
| Expired authorization reuse | Short timestamp window; paymaster validation data; no zero/unbounded expiry | Clock drift and bundler delays can waste approvals. Time boundary tests. |
| Malicious or stale bundler | Paymaster and account validate on-chain; bounded expiry; no inclusion guarantee | Can censor or delay within validity. Local external-bundler E2E proves transport, not liveness under attack. |
| Faulty RPC or stale code/nonce view | Block-referenced observations; chain and code identity checks; fail closed on inconsistent data | One RPC can lie consistently. Multiple endpoints improve availability, not consensus. RPC fault tests. |
| Omitted EntryPoint log or stale head | HTTP catch-up from a durable contiguous checkpoint; fail closed on reader errors and inconsistent block/log identity | A trusted RPC can omit events consistently; absence is not cryptographically proven. Reader eligibility and checkpoint tests. |
| Shallow or deep reorg | Keep provisional holds; store competing block hashes; roll back only within the configured depth | Deeper or terminal contradictions require manual intervention. Fork fixture tests. |
| False unused expiry | Require supplied time and confirmed canonical chain timestamp strictly beyond `validUntil`, complete scan coverage, and no canonical event | RPC omission remains a residual trust assumption. Unused and downtime tests. |
| Lost bundler response | Keep hold until canonical EntryPoint evidence or safe unused expiry; bind issued artifact to `userOpHash` | Bundler may censor indefinitely inside validity. Response-loss local scenario. |
| Duplicate event or consume/expire race | Unique fork observation identity; checkpoint then reservation then budget locks; one actual-spend row per sponsorship | PostgreSQL compromise remains out of scope. Two-worker and race tests. |
| Actual-cost overage | Preserve full observed cost; keep hold; durable anomaly and degraded readiness | Operator must reconcile treasury and ledger manually. Synthetic overage test. |
| Database partial failure or process crash | Phase 2 commits request, hold, counters, and audit together; same-key retry recovers the committed reservation after restart | Later artifact persistence and uncertain on-chain outcomes require separate recovery. Phase 2 cancellation, retry, and restart integration tests. |
| Duplicate logical request | Scoped idempotency key and canonical request fingerprint unique constraint | A new key can reserve again. Concurrent PostgreSQL and HTTP retry/conflict tests. |
| Emergency response failure | Off-chain disable plus on-chain paymaster pause; monitored control transaction | Already issued signatures remain valid until pause lands or expiry. Pause tests and operational drill. |
| Secret leakage in logs/config | Key references only, redacted request logs, no raw signatures in standard logs | Infrastructure logs and backups require access control. Static scan and log assertions. |
| Admin policy tampering | Authenticated publish, immutable versions, audit events | Authorized malicious operator can authorize loss. Change review and access separation are operational requirements. |

## Residual trust assumptions

The configured EntryPoint deployment matches the verified v0.9 code; the account implementation and paymaster are the project versions; PostgreSQL transactions and durable storage behave as configured; the signer key is protected and its access policy is enforced; the paymaster owner can pause; the RPC eventually supplies complete canonical logs and headers. A trusted RPC cannot cryptographically prove the absence of omitted events. None of these assumptions is replaced by a paymaster signature. This project does not claim an independent audit or production deployment.

Per-sender quota is keyed to the smart-account address; a user who controls multiple accounts can consume one quota per account. Target allowlisting constrains the immediate call, not any downstream behavior of the target contract. Deployment policy must select targets accordingly.

## Verification evidence plan

[Testing](testing.md) defines policy, parser, transaction race, Solidity mutation/invariant, and local E2E suites. [Failure matrix](failure-matrix.md) defines expected fail-closed behavior. Before a chain is enabled, record EntryPoint address/code hash, paymaster and account code hashes, finality setting, signer key ID, and approved policy version in deployment evidence.

Phase 1 implements static controls for chain and EntryPoint address abuse, target/selector substitution, gas and fee inflation, malformed execution calls, and policy disable. Phase 2 implements durable idempotency, capacity locks, unsigned expiry and release, and transactional audit. Phase 3 binds the original policy hash, domain, complete account calldata, gas fields, cost cap, and validity into one signed struct. Phase 4's paymaster checks that struct against actual EntryPoint operation fields. Phase 5 binds issuance to the EntryPoint operation hash and settles only after confirmed canonical evidence or finality-covered unused expiry. Phase 6 exposes a bounded scoped HTTP API, gates new issuance on reconciliation, signer, accounting, and deposit readiness, and requires an explicit recovery command for deep reorgs. [Evidence](evidence.md) maps these controls to tests. Production key custody and nonlocal deployment identity remain future work.
