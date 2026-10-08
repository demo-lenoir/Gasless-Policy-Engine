# Architecture

## Sponsorship path

```text
client / fixed smart account
  -> Go Policy API
  -> request normalization
  -> policy evaluation against immutable version
  -> PostgreSQL reservation and audit transaction
  -> canonical typed sponsorship payload
  -> SponsorSigner
  -> signed paymaster data persisted before response
  -> external bundler
  -> EntryPoint v0.9
  -> verifying paymaster
  -> fixed account execute(target, value, data)
  -> target call
  -> canonical EntryPoint event
  -> HTTP block/log reconciler
  -> PostgreSQL outcome and actual-spend transaction
```

The API returns paymaster fields for the client to assemble the final UserOperation. The client supplies its own account signature. The API is not a transaction broadcaster in v1. The external bundler may reject, delay, reorder, or omit the operation; it cannot bypass EntryPoint paymaster validation.

`internal/policy` implements only normalization and pure policy evaluation. Its inputs are a request draft, immutable `PolicySnapshot`, and explicit `EvaluationContext.Now`; it imports no HTTP, database, RPC, signer, bundler, or contract bindings. `Decision` carries the stable reason, policy version, derived call, cost upper bound, and validity window. `internal/admission` owns canonical request identity, `internal/store` owns PostgreSQL accounting, `internal/authorization` owns hashing and encoding, and `internal/issuance` coordinates the narrow signer. `internal/userop` builds and hashes the v0.9 packed operation from the same normalized request and durable artifact. `internal/reconcile` owns the HTTP chain reader and canonical scan; PostgreSQL owns checkpoint, fork evidence, and settlement. `cmd/localdemo` supplies disposable Anvil/PostgreSQL orchestration and submits through pinned Alto. `cmd/gasless` hosts the scoped HTTP service and watcher; `internal/httpapi` is the thin transport boundary. `internal/telemetry` observes committed off-chain outcomes. [Issuance](signing.md) defines the signing boundary.

## Component boundaries

| Component | Owns | Must not assume |
| --- | --- | --- |
| Client/account | Account authorization and operation submission; fixed `execute` ABI | That policy approval guarantees inclusion or target success. |
| Normalizer | Strict v0.9 field parsing, canonical hex/integer forms, exact ABI decoding | Client-provided target, selector, cost, or digest is authoritative. |
| Policy evaluator | Pure decision from normalized request, immutable policy snapshot, explicit evaluation time | That a later chain state remains unchanged. |
| Reservation store | Atomic all-chain, per-chain, and sender held-capacity updates, idempotency, append-only audit | In-memory mutexes provide financial correctness. |
| SponsorSigner | Sign a server-built digest using a narrow interface; report signer identity and failure | Permission to choose policy, fields, or arbitrary client messages. |
| Paymaster | Verify EIP-712 signature, exact operation fields, EntryPoint caller, cost cap, validity, pause state | Unsigned API claims, bundler behavior, or off-chain balances. |
| EntryPoint | Nonce, account/paymaster validation, sponsor deposit charge, operation events | Off-chain budget correctness. |
| RPC/reconciler | HTTP block/log catch-up, canonical ancestry, confirmed outcome evidence | That multiple providers constitute consensus or prove absence cryptographically. |

The signer interface exposes `Address(ctx)` and `SignDigest(ctx, digest32)`; only the issuer calls it after loading a durable reservation. The adapter returns no raw key. The local HTTP process uses a development signer supplied through environment configuration; production custody requires a separate adapter and controls. Signer access control should restrict the calling service and key; the narrow interface alone cannot prevent a fully compromised service from issuing valid approvals.

## Trust boundaries

1. **Client to API:** all UserOperation fields are hostile input. Decode exact single-call account ABI, reject noncanonical/trailing bytes, nonempty `initCode`, unsupported account code, and any client-selected paymaster signature or digest. The client may provide an unsigned v0.9 operation draft and idempotency key.
2. **API to PostgreSQL:** the database is the authoritative reservation ledger. Policy versions are immutable once published. The API cannot sign until the reservation transaction commits. Database errors fail closed.
3. **API to signer:** only a canonical digest generated after reservation crosses this boundary. A signer outage leaves no approval. Signed artifacts are persisted before delivery.
4. **API to RPC:** chain observations are fallible. The configured chain, EntryPoint code identity, account code identity, nonce, and fee inputs are checked against a referenced block; stale or inconsistent observations fail closed. Multiple endpoints improve availability, not consensus.
5. **Client to bundler to chain:** a bundler is untrusted for policy correctness. The paymaster validates all cryptographic constraints on-chain. The account separately validates its owner signature.
6. **Operator to policy/paymaster:** policy publication and emergency controls require authenticated operator authority. Off-chain disable blocks issuance at the durable artifact transaction; an in-flight signer result is discarded if disable committed first. The paymaster owner's on-chain pause blocks outstanding authorizations after its transaction lands. These controls have different propagation delays.

## Exact-operation authorization

V1 uses `DemoAccount`, a fixed, nonupgradeable single-call account. `PolicyPaymaster` compares the sender's runtime code hash to the approved fixed-account code hash; without this check, another account could interpret identical `callData` differently. The operation's outer `callData` must be the canonical ABI encoding of `execute(address,uint256,bytes)`. The inner target, value, and calldata are extracted off-chain for policy evaluation. The signed complete outer calldata hash binds them, and the paymaster hashes the actual operation bytes. It compares all packed operation fields to the signed commitment. Account signature bytes and paymaster signature suffix are excluded from the sponsor digest; account authorization remains the account's responsibility. [ADR 0002](adr/0002-sponsorship-signing.md) specifies the commitment.

The policy evaluator enforces static allowlists; the admission store enforces quotas and budgets before signing. The paymaster does not replicate mutable allowlists or database counters; it verifies the exact signed authorization and on-chain pause state. It returns empty validation context and does not call `postOp`; the signed post-operation gas limit is zero. EntryPoint's `UserOperationEvent` reports actual gas cost and success even when target execution reverts. A policy edit does not revoke issued signatures until expiry. The paymaster owner's pause blocks outstanding artifacts after its transaction lands.

## Accounting and reconciliation

Admission resolves idempotency and reserves all-chain, per-chain, and sender capacity in one transaction. Issuance calls the signer outside database locks and commits the checked artifact and expected `userOpHash` together. The reconciler scans bounded canonical blocks over HTTP; checkpoint advancement commits with observations. Before finality, the economic hold remains `RESERVED`. A settlement transaction locks checkpoint, reservation, then all-chain, per-chain, and sender budget rows; it records exact EntryPoint `actualGasCost`, returns unused hold, and appends audit. A signed authorization expires unused only after a confirmed canonical chain-time watermark beyond `validUntil` and complete log coverage. Terminal contradictions and overage stop automatic settlement. The off-chain budget limits issuance; the EntryPoint deposit funds actual gas. Neither balance proves the other. [Accounting](accounting.md), [reconciliation](reconciliation.md), and [ADR 0005](adr/0005-outcome-finality.md) specify the boundaries.

## Observability

The HTTP layer authenticates one configured client scope, parses a bounded JSON draft, then calls the existing admission and issuance services. The read projection queries PostgreSQL and does not reinterpret policy. A periodic worker runs the existing reconciler. The API emits bounded-label metrics; the database retains per-request identifiers and digests. Optional OTLP/HTTP trace export spans the transport, policy, admission, signer, reader, and settlement boundaries. [Observability contract](observability.md) fixes names and cardinality rules.
