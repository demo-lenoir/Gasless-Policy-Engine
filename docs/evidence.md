# Verification evidence

## Phase 1 static policy

| Claim | Evidence |
| --- | --- |
| Target, selector, and value come from canonical single-call account calldata | `TestDecodeExecuteCanonicalAndNestedBytes`, `TestDecodeExecuteRejectsAmbiguousForms`, `TestNormalizeDeterministicAndCanonical`, `FuzzDecodeExecute` in [decoder tests](../internal/policy/call_test.go) and [fuzz tests](../internal/policy/fuzz_test.go). |
| Wrong chain, target, selector, denied sender/target, or disabled policy cannot pass static admission | `TestEvaluateStaticRulePrecedence`, `TestSelectorIsScopedToTargetAndChain`, `TestSecurityFieldMutations` in [evaluation tests](../internal/policy/evaluate_test.go). |
| Every v0.9 prefund gas component and fee cap is bounded | `TestNumericBoundaries`, `TestEstimatedCostAndValidityBounds`, and `TestSecurityFieldMutations`; [policy behavior](policy.md) names the field set. |
| Ethereum quantities do not silently narrow or overflow | `TestUint256ParsingAndCheckedArithmetic`, malformed normalization cases, and checked `EstimatedUpperBound`. |
| Snapshot order and caller mutation do not change decisions | `TestSnapshotOrderingAndInputMutationDoNotChangeDecision`, `TestEvaluateAllowedAndEstimatedUpperBound`, and `FuzzNormalize`. |
| Configuration and validity windows fail closed | `TestSnapshotRejectsInvalidConfiguration`, `TestSnapshotJSONRejectsUnknownDuplicateAndTrailing`, `TestEstimatedCostAndValidityBounds`. |
| The package has no infrastructure dependency | Production imports in `internal/policy` are Go standard library only; `make verify-phase1` runs tests, vet, race detector, and fuzz smoke. |

## Phase 2 durable admission

| Claim | Evidence |
| --- | --- |
| Fingerprint is canonical and commits normalized security fields | `TestFingerprintCanonicalAndFieldMutation` changes chain, EntryPoint, sender, nonce, account call, target, selector, inner bytes, value, every gas and fee field, and requested lifetime. |
| Limits reject zero, negative, overflow, asset mismatch, and duplicate chain configuration | `TestLimitsRejectInvalidConfiguration`; the example config is loaded through the same validator. |
| Equivalent configuration order has one published identity | `TestPublishedSnapshotHashIgnoresConfigurationOrder` reorders target, selector, and denylist entries without changing the configuration hash. |
| All-chain and per-chain budget admission cannot oversubscribe | `TestBudgetAndQuotaRaces` runs three 100-way all-chain races with exactly 10 accepts and 90 denials each; `TestChainBudgetAndIndependentSenders` proves chain cap denial. `TestMidnightRaceAndLastBudgetSlot` covers the last slot and UTC rollover. |
| Sender quota cannot oversubscribe or consume another sender's slot | `TestBudgetAndQuotaRaces` runs three 100-way sender races with exactly 20 accepts and 80 denials each; `TestIndependentSenderQuota` admits one request per sender. |
| Idempotency survives concurrent duplicates, conflicts, restart, and policy change | `TestIdempotencyRacesAndRestart` launches 100 identical calls and reopens the pool; `TestConflictingIdempotencyRace` launches 100 calls split across two fingerprints under one key. |
| State transitions return held capacity once and retain admission count | `TestLifecycleAndAudit`, `TestConsumeAndIllegalTransitions`, `TestTerminalTransitionRaces`, and `TestTwoExpiryWorkers` cover repeat calls and competing transitions. |
| Request, reservation, counters, and audit share a transaction | `TestLifecycleAndAudit`, `TestStaticDenialIsAuditedWithoutReservation`, `TestDatabaseCancellationLeavesNoPartialAdmission`, and `TestBoundedSerializationRetry`. |
| Emergency and dependency failures deny admission | `TestEmergencyDisableDeniesBeforeReservation`, `TestUnavailableDatabase`, and cancellation/lock-timeout tests. |
| Metrics observe committed outcomes and can recover gauges from the ledger | `TestCommittedMetricsAndLedgerRefresh`. |
| Migrations execute on clean PostgreSQL and race tests use a real server | `scripts/verify_phase2.py` creates two disposable PostgreSQL databases, applies all forward migrations, checks six tables and critical indexes, and runs the integration suite normally and under `go test -race`. |

Phase 2 evidence establishes static eligibility and unsigned durable admission. It does not establish signer correctness, on-chain paymaster validation, replay rejection, chain outcome reconciliation, or end-to-end UserOperation success.

## Phase 3 authorization issuance

| Claim | Evidence |
| --- | --- |
| Canonical typed authorization binds every operation field and domain | `TestDigestBindsEveryField` mutates the chain, paymaster, EntryPoint, sender, nonce, account code hash, calldata hash, gas and fee words, cost, policy identity, sponsorship ID, and validity. |
| One committed vector has equal Go and Solidity domain, struct hash, digest, signature recovery, and byte encoding | `TestCommittedVector` and Foundry `testCommittedVector` both load `testdata/authorization-vector.json`. |
| Wrong signer, malformed signature, wrong recovery byte, high-s signature, and late signer response fail | `TestDevSignerCanonicalSignature`, `TestSignerIdentityAndSignatureFailures`, and `TestSignerResponseAfterDeadlineIsDiscarded`. |
| Exactly one artifact and signer call under concurrent retries | `TestSigningConcurrentAndRestart` runs 100 concurrent calls and checks one issued audit event and exact artifact recovery after a new database pool opens. |
| A lost claim or uncommitted signature cannot change the durable authorization identity | `TestSigningClaimCrashBoundaries` fences the old claim; `TestInterruptedSignerCallRecoversAfterLease` and `TestCrashAfterSignatureBeforeCommit` recover after interrupted signer I/O and a simulated pre-commit process stop. |
| Emergency disable and expiry during signer latency prevent artifact commit | `TestEmergencyDisableDuringSigning`, `TestSigningPostSignExpiryAndClaimFence`, and `TestUnsignedExpiryRacesSignerReturn` synchronize the signer with durable state changes. |
| An issued artifact is immutable and keeps its economic hold | `TestArtifactFieldsImmutable` rejects SQL mutation; `TestSigningFailuresAndExpiryHold`, `TestSigningAtLastInstantBeforeExpiry`, and `TestConcurrentSignedExpiryWorkers` check validity boundaries, one elapsed audit marker across workers, and the held budget row. |
| Old idempotent admission retains its original approval snapshot | `TestRetryAfterPolicyUpdateKeepsOriginalApproval` retries through a newer policy and requires the original version for issuance. `TestIssuanceProfileCannotChangeWithinPolicyVersion` rejects a paymaster change. |
| Issuance profile is bound at admission | `TestIssuerProfileValidationAndSnapshotIdentity` rejects malformed profiles and commits profile changes to the policy hash; `TestIssuanceProfileBoundBeforeFirstClaim` rejects same-version profile changes at admission and before the first signer call; `TestWrongChainIssuerCannotClaimReservation` rejects another chain without changing the admitted profile. |
| Migrations and race tests execute on PostgreSQL | `make verify-phase3` runs the inherited two-fresh-database migration/integration gate, ordinary and race-enabled Go tests, Go fuzz smoke, and Foundry tests. |
| Signing metrics use bounded reasons and count issued artifacts once | `TestSigningMetricsTrackCommittedOutcome` covers issuance, retry, emergency denial, signer error, and elapsed artifact observation. |

The Solidity contract is a reference verifier. These tests do not establish an EntryPoint-facing paymaster, on-chain replay behavior, outcome reconciliation, or a real gasless operation.

## Phase 4 local chain integration

| Claim | Evidence |
| --- | --- |
| Real Go-issued authorization validates on-chain | `scripts/verify_phase4.py` admits against fresh PostgreSQL, issues a durable artifact, builds a PackedUserOperation, and exercises direct EntryPoint and pinned Alto `eth_sendUserOperation` paths. Both require `SponsorshipValidated` and successful `UserOperationEvent` for the same hash. |
| A zero-native-balance account executes an allowed call | The local verifier checks account balance before and after as zero, `DemoCounter.count() == 1`, and an EntryPoint operation receipt. |
| The paymaster deposit funds gas | The verifier deposits one ether, checks that the balance decreases, and equates that delta with `UserOperationEvent.actualGasCost`. `testDirectEntryPointPaysForZeroBalanceAccount` covers the same boundary in Foundry. |
| Signed operation mutations fail | `testMutationsFailPaymasterValidation` and `testDomainAndAccountIdentity` mutate calldata, target, value, nonce, account gas, pre-verification gas, fees, paymaster gas, policy identity, sponsorship ID, validity, initCode, chain, paymaster, and sender. The Go E2E also changes calldata after issuance and refreshes the owner signature before requiring sponsor rejection. |
| Exact replay cannot execute twice | Both local verifier paths simulate the exact second operation and require EntryPoint rejection; `testDirectEntryPointPaysForZeroBalanceAccount` checks the unchanged target count. |
| On-chain pause blocks an issued artifact | `testPauseAndExpiry` attempts the authorized operation while paused, then unpauses and succeeds inside the same window. `testValidityBoundariesAndAccess` checks admin access and timestamp edges. |
| Malformed paymaster data fails closed | `testMalformedAndInsufficientDeposit` and `testFuzzMalformedPaymasterLength` exercise short, altered, and unsupported lengths. Phase 3's Go/Solidity committed vector checks the exact 116-byte data and 243-byte outer layout. |
| Failed target execution still costs sponsor gas | `testExecutionRevertStillChargesPaymaster` observes `UserOperationEvent(success=false, actualGasCost>0)`, unchanged target state, and a decreased paymaster deposit. Empty validation context and zero post-operation gas mean no `postOp` callback is made. |
| Insufficient EntryPoint deposit rejects independently of PostgreSQL limits | `testMalformedAndInsufficientDeposit` withdraws the deposit, then requires EntryPoint submission to revert. |
| Dependencies and local deployment are reproducible | A Gitlink pins account-abstraction; the manifest and checksummed source bundles pin OpenZeppelin and Alto snapshots. The verifier requires Foundry/Anvil 1.8.4, builds Alto with pnpm 8.15.4, and runs two disposable local chains/databases. The ignored deployment metadata records addresses, transactions, code hash, compiler/tool versions, and source revisions. |

These claims apply to the local Anvil chain and test-only keys. Issued reservations are not reconciled with chain outcomes in Phase 4.

## Phase 5 outcome reconciliation

| Claim | Evidence |
| --- | --- |
| Issued artifact binds one v0.9 operation identity | `internal/userop.Hash` reproduces `getUserOpHash`; the direct and Alto local runs compare hashes before account signing. Authorization commit persists the hash atomically with the artifact. |
| Confirmed success and reverted execution both consume actual cost | `TestReconciliationFinalityAndCost` checks one, two, and three confirmations, `success=true/false`, exact ledger cost, and conservation. `scripts/verify_phase5.py` runs a real reverted target call and checks PostgreSQL settlement. |
| Unused signed authorization returns capacity only after chain coverage | `TestReconciliationUnusedExpiry` exercises a confirmed block timestamp beyond `validUntil`; local `unused` and `unknown-no-inclusion` scenarios mine past validity and settle `EXPIRED_UNUSED`. |
| Lost Alto submission response does not release a hold | The local response-loss proxy forwards `eth_sendUserOperation` to Alto and drops its HTTP response. The client recovers by expected hash; the watcher consumes the included operation after confirmations. |
| Reorgs retain fork evidence and provisional holds | `TestReconciliationReorgAndReinclusion` retains orphan and canonical observations, then settles once on reinclusion. `TestReconciliationOverageAndDeepReorg` stops on a branch beyond the automatic depth. |
| Terminal contradiction and overage fail closed | `TestReconciliationTerminalReorgRequiresManual` preserves consumed accounting and degrades readiness. Synthetic overage retains the full observed cost and the hold. |
| Worker concurrency does not double settle | `TestReconciliationTwoWorkersAndRestart` uses two database handles after an observed event; `TestReconciliationExpiryVsInclusion` races workers near validity/finality. Each checks one terminal result. |
| Fresh database and race-enabled tests pass | `scripts/verify_phase2.py` applies all forward migrations to two disposable PostgreSQL databases and runs `internal/store` tests normally and under `-race`; `make verify-phase5` includes the inherited gate and local scenarios. |

These results are local reference evidence. The RPC reader is trusted for completeness, and the configured confirmation count is not universal finality. See [reconciliation](reconciliation.md).

## Phase 6 service and local release

| Claim | Evidence |
| --- | --- |
| HTTP rejects malformed, unknown, duplicate, and oversized fields and does not accept client digests | `TestHTTPIdempotencyAndRequestBoundary` and the bounded decoder in [HTTP tests](../internal/httpapi/server_test.go). |
| A scoped retry recovers the same durable artifact and a changed request conflicts | The HTTP test covers retry and conflict. `make demo` exercises PostgreSQL-backed HTTP create, retry, conflict, and twenty concurrent retries, comparing sponsorship ID and artifact bytes. |
| Readiness reflects reconciliation, accounting, signer, and EntryPoint deposit state | [HTTP server](../internal/httpapi/server.go), `TestHealthAndStatus`, and the full local demo's status/metrics check. The paymaster deposit comes from EntryPoint `balanceOf`; the database budget remains a separate control. |
| Deep-reorg recovery requires an explicit safe plan and preserves terminal history | `TestDeepReorgOperatorRecovery` and the offline [recovery command](../cmd/reconcile-recover/main.go); the dry run reports terminal conflicts and replay retains `MANUAL_INTERVENTION` until convergence. |
| Full local HTTP-to-chain flow conserves the original hold | `make demo` uses pinned Alto and EntryPoint, then [demo assertions](../scripts/verify_phase6.py) check one consumed operation, one unused signed expiry, exact actual-cost row, deposit delta, released hold, and checksum. |
| Local release artifacts are tied to committed source | `make verify-phase6` runs the prior gates, fresh PostgreSQL, vulnerability and container scans, and [isolated clone verification](../scripts/clean_clone_verify.py) before [unsigned artifact generation](../scripts/release_local.py). Hosted CI is pending publication. |

These results apply to the local chain and development signer. The prepared [hosted workflow](../.github/workflows/phase6.yml) has no result until it runs against a published source commit.
