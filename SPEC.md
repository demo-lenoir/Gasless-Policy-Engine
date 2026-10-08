# Gasless Policy Engine specification

## Problem and decision

A product wants gasless user experience: users should not need native gas tokens to invoke approved functions. The sponsor's EntryPoint deposit is financially exposed. Without a policy layer, a malicious or buggy client can submit unlimited sponsored operations, call unsupported targets or selectors, inflate gas, replay approvals, exhaust per-user quota, or drain a global budget. Cross-chain and cross-paymaster reuse are additional authorization risks.

The service answers: **Should this exact UserOperation be sponsored under this exact policy snapshot?** The answer is deterministic for the normalized request and immutable policy version, and is recorded with its reason. External chain state used for eligibility (nonce, code identity, balance, fee estimates) is captured as an explicit decision input with block reference; it is not treated as consensus. Signature issuance additionally requires a successful reservation and a healthy signer.

## Scope

Final v1 covers EntryPoint v0.9, a fixed single-call smart account, an external v0.9 bundler, a minimal verifying paymaster, a Go policy API, chain/target/selector allowlists, gas and call-value bounds, per-sender quota, a global daily budget, short expiry, sender/target denylist, emergency disable and on-chain pause, EIP-712 sponsorship authorization, PostgreSQL audit and reservation accounting, a signer interface suitable for KMS/HSM adapters, Prometheus metrics and OpenTelemetry traces, and a local end-to-end demo.

V1 accepts an already deployed project account with `execute(address,uint256,bytes)` only. `initCode` is empty; EIP-7702, batches, account upgrades, aggregators, arbitrary account ABIs, and arbitrary paymasters are excluded. A call with nonzero value may be allowed only within policy limits and must be funded by the account; the sponsor pays gas, not call value. The local demo uses zero call value.

The v1 paymaster returns empty validation context and performs no `postOp` accounting. Its post-operation gas limit is zero. Finalized EntryPoint events provide actual gas charges to the off-chain ledger.

## Non-goals

Custom bundler; full smart-account wallet platform; custody or wallet key management; universal policy DSL; cross-chain sponsorship framework; token bridge; MEV protection; production billing/accounting; production HSM integration in v1; treating multiple RPC providers as consensus. This design does not guarantee inclusion, execution success, or immunity to chain reorgs.

## Version decisions

Verified upstream release and source information is recorded in [ADR 0001](docs/adr/0001-upstream-versions.md). The v0.9 deployment metadata discrepancy and local strategy are in [ADR 0004](docs/adr/0004-local-entrypoint-deployment.md).

| Component | Decision | Constraint |
| --- | --- | --- |
| EntryPoint and interfaces | `eth-infinitism/account-abstraction` `v0.9.0`, EntryPoint `0x433709009B8330FDa32311DF1C2AFA402eD8D009` | Verify deployed code hash per chain before enabling sponsorship. |
| Smart account | Project-owned, fixed single-call account using v0.9 `IAccount` / `BaseAccount` semantics | Deployed account code identity is allowlisted; no upgrade path in v1. |
| Paymaster | Project-owned `IPaymaster` / `BasePaymaster` v0.9 integration | Account and paymaster signatures are distinct; use v0.9 signature suffix. |
| OpenZeppelin Contracts | `v5.7.0`, commit `cab19933c33c2ad1d4c7a84864a3601dddfd16f3` | Pinned Solidity dependency compatible with `0.8.37`. |
| Solidity / Foundry | Solidity `0.8.37`; verified with Foundry/Anvil `v1.8.4-Homebrew` | Compiler is pinned by `foundry.toml`; Foundry version is a tested tool version. |
| Go / go-ethereum | Go `1.27.1`; go-ethereum `v1.17.7` | Ethereum hashing, signatures, ABI, and local RPC integration. |
| External bundler | Alto commit `96529592b67a69be23c013359cbc9990657af64a`; pnpm `8.15.4` | Separate local process; v0.9 support exercised by `eth_sendUserOperation`. |

## Actors and responsibilities

The client owns the account signature and submits to an external bundler. The API normalizes and evaluates requests, holds policy authority, and constructs typed authorization. PostgreSQL owns durable request, reservation, and audit state. `SponsorSigner` signs only a server-built digest. The paymaster checks the signed fields, EntryPoint caller, validity range, cost cap, and pause state. EntryPoint enforces account nonce and charges the paymaster deposit. The bundler transports operations and is not a policy authority. See [architecture](docs/architecture.md).

## Invariants

### Signature and replay

- The domain contains `chainId` and the verifying paymaster address. The struct contains the EntryPoint address and a nonzero policy version and sponsorship ID.
- The struct commits to sender, approved fixed-account code hash, EntryPoint nonce, `initCode` hash (empty in v1), complete account `callData` hash, account gas limits, pre-verification gas, fee caps, paymaster gas limits, reserved cost cap, and `validAfter` / `validUntil` timestamps. The target, inner calldata, selector, and call value are bound by the complete canonical outer calldata hash.
- Changing chain, paymaster, EntryPoint, sender, account code identity, nonce, target, calldata, call value, gas or fee fields, cost cap, validity window, sponsorship ID, or policy version invalidates the authorization. The server builds canonical typed data; clients cannot submit digests or opaque messages to sign.
- Authorizations have a bounded lifetime and use timestamp validity only. The EntryPoint nonce prevents successful on-chain replay of the same operation. Sponsorship IDs are unique off-chain identifiers, not an on-chain replay registry. See [ADR 0002](docs/adr/0002-sponsorship-signing.md).
- A client may request a duration, not absolute validity timestamps. The service rejects durations outside the published policy range and derives timestamps from explicit evaluation time. Omitted duration uses the policy default; no clamping occurs.

### Policy

- Disallowed chain, target, or inner function selector is never signed. Denylisted sender or target is never signed. Outer account call must be the canonical single-call selector and encoding.
- Inner calldata must have at least four bytes; fallback and receive calls are out of scope. Token amounts embedded in inner calldata are bound byte-for-byte by its hash, even when no separate amount parser exists.
- Gas and fee bounds, estimated maximum sponsor cost, and call value are checked before reservation. Unsupported account code or nonempty `initCode` is rejected.
- Policy evaluation is pure over normalized request, immutable policy snapshot, and explicit external observations. The policy version is stored in the decision and signed authorization. A policy edit creates a new version; ordinary edits affect new requests only. Emergency disable stops new signatures; the paymaster owner's on-chain pause blocks outstanding unexpired authorizations.

### Budget and quota

- UTC daily all-chain, per-chain, and per-sender Wei capacity include consumed spend plus held reservations. The all-chain cap requires configured chains to declare one native gas asset. The sender count quota charges each admitted request even after its hold is released or expires. Concurrent requests cannot oversubscribe any cap. Reservation commits before any later signing step; a failed reservation cannot produce a signature.
- Each reservation moves `RESERVED -> CONSUMED`, `RESERVED -> EXPIRED`, or `RESERVED -> RELEASED` once. Uncertain chain outcomes remain held as `RESERVED` until reconciled; timeout alone is insufficient proof of non-inclusion.
- Gas costs and limits use checked integer arithmetic, represented as integer wei or exact decimal `NUMERIC(78,0)` in PostgreSQL. No floating-point amounts.

### Keys and chain

- Application code does not load seed phrases or return raw key material. Signer failures fail closed, with no unsigned fallback.
- The paymaster verifies exactly the typed fields, including sender code hash and complete account calldata hash, against the actual `PackedUserOperation`; it does not trust unsigned policy claims. It rejects expired signatures and accepts only EntryPoint calls. A modified approved operation cannot execute under the old sponsor signature.
- The sponsor's off-chain budget is a financial control, not an on-chain spending cap. During a database, API, or signer outage, previously issued signatures remain usable until expiry unless the paymaster is paused or signer key is revoked.

## State and transaction boundary

The request is normalized before the transaction. A PostgreSQL transaction resolves idempotency, verifies the immutable policy/accounting/issuance-profile configuration hash, publishes the issuance profile for the chain when configured, records the decision, locks emergency control then all-chain, per-chain, and sender rows, holds capacity, and commits the reservation and audit events together. Issuance uses a fenced claim, an external signer call, and a separate artifact transaction with emergency and expiry rechecks. The artifact transaction also persists the expected v0.9 `userOpHash`. Unsigned holds can expire at their validity deadline. Issued holds require confirmed canonical outcome or finality-covered unused expiry. See [ADR 0003](docs/adr/0003-budget-reservations.md), [ADR 0005](docs/adr/0005-outcome-finality.md), [accounting](docs/accounting.md), [reconciliation](docs/reconciliation.md), and [issuance](docs/signing.md).

## Failure posture

Security-sensitive uncertainty fails closed. PostgreSQL, signer, and required RPC failure prevent new approvals. Bundler failure does not authorize a replacement operation. An unknown on-chain outcome holds capacity until resolved. The complete [failure matrix](docs/failure-matrix.md) specifies retries and responses.

## Implemented in Phase 1

`internal/policy` implements strict decimal and hex normalization, canonical decoding of the fixed account's `execute(address,uint256,bytes)` call, immutable static policy snapshots, per-chain EntryPoint/target/selector rules, sender and target denylist, call value and every v0.9 prefund gas/fee field cap, an estimated sponsor cost upper bound, emergency disable, and bounded duration selection from explicit evaluation time. See [policy behavior](docs/policy.md) and [evidence](docs/evidence.md). Static approval is eligibility only. Account code identity and live nonce/code observations remain future work.

## Implemented in Phase 2

`internal/admission` computes a canonical security-field fingerprint, keeps static policy separate from durable admission, and returns stable policy or accounting reasons. `internal/store` executes forward PostgreSQL migrations in the test gate and provides durable idempotency, atomic all-chain/per-chain/sender admission, terminal reservation transitions, bounded unsigned expiry batches, and audit events in the same transactions. `internal/telemetry` records bounded-label Prometheus metrics after committed operations. At the Phase 2 boundary the service core had no HTTP endpoint or signing path. [Accounting](docs/accounting.md) specifies the exact boundaries and limitations.

## Implemented in Phase 3

`internal/authorization` constructs canonical EIP-712 sponsorship digests and the exact v0.9 paymaster byte layout. `internal/signing` defines the narrow signer interface and explicit development signer; `internal/issuance` signs only durable admitted reservations. PostgreSQL persists an immutable issuance profile, fenced signing claim, checked signature artifact, and audit transition. Pre-sign and commit-time checks enforce emergency disable, policy-version revocation, reservation state, and the original validity window. Go and Solidity reference tests share one committed vector. Signed holds remain reserved until later outcome reconciliation. The core has no HTTP runtime, production paymaster, bundler interaction, contract deployment, or chain transaction. [Issuance](docs/signing.md) records the exact boundary.

## Implemented in Phase 4

`PolicyPaymaster` inherits the pinned v0.9 `BasePaymaster`, checks the exact Phase 3 authorization against actual `PackedUserOperation` fields, enforces fixed-account runtime code identity and an empty `initCode`, and allows the owner to pause validation. It returns empty context and uses zero post-operation gas; EntryPoint emits actual gas cost and success. `DemoAccount` is a nonupgradeable owner-signed account using v0.9 `BaseAccount`. `internal/userop` builds the packed operation from the normalized request and durable artifact. Two clean local paths execute the operation: direct EntryPoint submission and pinned Alto `eth_sendUserOperation`. Both use PostgreSQL admission and Go issuance.

## Implemented in Phase 5

The issued artifact transaction persists a locally reproduced `userOpHash`, checked against EntryPoint on the local chain. `internal/reconcile` scans HTTP block headers and filtered EntryPoint logs from a durable checkpoint. PostgreSQL retains fork identities and provisional observations. Three local confirmations allow a canonical event to settle actual Wei cost, including `success=false`, while returning unused hold to the original admission period. A confirmed canonical timestamp strictly beyond `validUntil`, complete scan coverage, and absence of a canonical event allow unused signed expiry. Reorgs within eight blocks reset provisional observations; deeper or terminal contradictions and cost overage degrade readiness for manual intervention. See [reconciliation](docs/reconciliation.md).

## Implemented in Phase 6

The scoped local HTTP service delegates normalization, policy, admission, and issuance to the existing application layers. It exposes durable sponsorship creation and read projections, bounded operational status, liveness, readiness, and Prometheus metrics. The offline recovery command provides a dry run and bounded replay for a safe deep reorg; terminal accounting conflicts remain manual. `make demo` exercises HTTP issuance through Alto and EntryPoint, then checks actual-cost settlement and unused signed expiry. `make verify-phase6` is the local release gate and produces unsigned source-bound artifacts after clean-clone verification. See [operations](docs/operations.md) and [local release](docs/release.md). Production signer custody and public-chain deployment remain outside this implementation.

## Phase acceptance criteria

| Phase | Acceptance criteria |
| --- | --- |
| 0: foundation | All documents, API skeleton, schema, and version decisions agree; `make verify-phase0` passes; no runtime signing/sponsorship logic, secrets, or local paths; clean committed tree. |
| 1: deterministic policy | Implemented: normalizer and evaluator reject unsupported account shape, chains, targets, selectors, bounds, and denylist; table and fuzz tests cover canonical equivalence and boundary values; no signing or funds movement. |
| 2: durable accounting | PostgreSQL idempotency, request/audit writes, transactional all-chain/chain/sender reservations, unsigned expiry and terminal transitions, and concurrent race tests pass. |
| 3: authorization | Implemented: typed-data vectors match Go and a Solidity reference verifier; the signer interface is narrow; durable fenced issuance, emergency recheck, signer recovery, and restart-safe artifact retry pass. This is not an EntryPoint-facing paymaster. |
| 4: local chain integration | Implemented: EntryPoint-facing paymaster, fixed account, pinned external bundler, local deployment, direct and bundler end-to-end paths, mutation/replay/pause tests, zero-balance account and sponsor deposit evidence. Unknown outcomes stay reserved. |
| 5: outcome reconciliation | Implemented: durable userOp binding, canonical HTTP catch-up, provisional fork evidence, confirmed actual-cost settlement, finality-covered unused expiry, bounded reorg recovery, anomaly fail-closed behavior, and local direct/bundler accounting scenarios. |
| 6: local service and release | Scoped HTTP authorization/status, readiness, explicit deep-reorg recovery, complete local demo, container and clean-clone gates, vulnerability scan, SBOM, and unsigned provenance. Hosted CI remains pending publication. |

`make verify` aliases the local Phase 6 release gate. It does not establish hosted CI or production deployment.
