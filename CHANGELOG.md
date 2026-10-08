# Changelog

## Unreleased

- Establish the Phase 0 specification, threat model, architecture, ADRs, API contract, schema design, and validation gate.
- Add a pure Go static policy evaluator with strict account-call decoding, snapshot validation, boundary and mutation tests, and fuzz targets.
- Add PostgreSQL-backed idempotent admission, daily all-chain/per-chain budgets, sender quota, reservation transitions, transactional audit, committed metrics, and concurrency verification.
- Add canonical EIP-712 authorization, a development signer boundary, fenced signing claims, immutable artifacts, shared Go/Solidity vectors, and emergency recheck tests.
- Add a pinned v0.9 EntryPoint paymaster, fixed account, and direct and external-bundler local execution with mutation, replay, pause, and gas-funding evidence.
- Add durable v0.9 UserOperation identity, HTTP block/log reconciliation, bounded fork recovery, confirmed actual-cost settlement, safe unused expiry, and accounting evidence.
- Add scoped sponsorship/status HTTP endpoints, readiness and deposit monitoring, explicit deep-reorg recovery, complete local API demo, container build, security scans, and unsigned local release evidence.
