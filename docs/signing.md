# Authorization issuance

Phase 3 takes a durable approved reservation to one immutable EIP-712 authorization artifact. Phase 4's local integration passes that artifact to `PolicyPaymaster` through a real PackedUserOperation. The exact cryptographic format is in [ADR 0002](adr/0002-sponsorship-signing.md).

## Issuance boundary

The caller passes only a sponsorship ID. `internal/issuance` loads the normalized request, original policy version and hash, reservation amount, and validity from PostgreSQL. The store recomputes the canonical request fingerprint and checked cost bound before granting a fenced claim. Admission publishes an immutable issuance profile in the same transaction as the original request: paymaster, EntryPoint, fixed-account code hash, and expected signer for its chain. The profile is part of the canonical policy hash. A later issuer with different values receives `POLICY_VERSION_CONFLICT` before the first signer call; a request admitted without a profile cannot be signed. A profile change requires a new policy version. A policy version may be explicitly marked `issuance_revoked` without modifying its published snapshot; that revocation cannot be reversed in the same version.

The issuer builds the typed struct and digest locally, obtains `SponsorSigner.Address`, and checks the durable gate immediately before `SignDigest`. It discards a response returned after either signer context deadline, even if the adapter returned a valid signature. A short final transaction rechecks the claim token and generation, reservation status, expiry, emergency row, policy revocation, profile, and absence of an artifact. Signature length, low-s form, v value, and recovered signer address are verified before this transaction. The signer call holds no database lock. A competing claim can replace an expired lease; the old worker's result then fails the fencing check. The signer interface does not choose policy, validity, or the digest source.

The local signer requires an explicit development flag. Application code never receives a private-key byte slice from the signer interface. A cloud custody adapter can implement the same two methods later. The interface alone does not protect against a compromised issuer or signer infrastructure; deployment access controls remain necessary.

The checked-in admission example omits `issuance_profiles` because it does not identify a deployed fixed account or paymaster. It can exercise admission but cannot issue an artifact. Issuance requires a validated profile for every configured chain; its account code hash and expected signer must match the intended deployment. Changing either requires a new policy version.

## Recovery and time

Claims have a lease and monotonically increasing generation. A crash before or during signing leaves no artifact; after lease expiry another process reconstructs the same digest and sponsorship ID. A signature returned but not committed is discarded; retry may sign the same digest again. A committed artifact is read, recomputed, and returned byte-for-byte without another signer call. A missing or inconsistent persisted artifact fails closed.

The admitted `validAfter` and `validUntil` never move on retry. New signing stops at `now >= validUntil`. EntryPoint's timestamp rule is stricter at `validAfter` (`block.timestamp > validAfter`) and inclusive at `validUntil`. The signed authorization carries these exact timestamps. The issuer does not claim an on-chain result merely because it signed.

Unsigned reservations can expire and return held Wei. Issued artifacts remain held even after `validUntil` until confirmed outcome reconciliation. A bounded worker records `AUTHORIZATION_EXPIRED` after the deadline and retains the economic hold. The Phase 5 reconciler consumes exact EntryPoint cost or expires unused capacity after confirmed chain-time coverage. This prevents capacity from being reused while the chain outcome is unknown.

An emergency disable that commits before the artifact transaction blocks issuance, including while the signer is in flight. It cannot revoke an artifact already committed. The Phase 4 paymaster owner can pause on-chain validation of outstanding signatures; unpause restores eligibility if the signed window and nonce still permit it.

## PostgreSQL boundaries

1. Admission commits request identity, original policy snapshot and issuance profile, budget hold, and audit.
2. Claim locks the reservation, reads the immutable policy row, validates the issuance profile, and commits claim token, generation, lease, and `SIGNING_CLAIMED` audit.
3. Signer I/O occurs with no SQL transaction open.
4. Finalization locks and rechecks the reservation, policy version, issuance profile, and emergency row; it commits artifact bytes and `AUTHORIZATION_ISSUED` audit together.
5. A failed signer call clears its owned claim and writes `SIGNING_FAILED`; emergency blocking writes `SIGNING_BLOCKED_EMERGENCY`. The audit uses bounded reason codes and can record the digest and signer address without copying signature bytes.

All store operations use caller context and a configured database timeout. Admission and signing remain separate transactions; a failed signing attempt retains its reservation while valid. A timeout or storage error never returns a signature. Ordinary metrics observe completed issuance only after commit.

## Stable issuance reasons

`AUTHORIZATION_ISSUED`, `AUTHORIZATION_ALREADY_ISSUED`, `SIGNING_IN_PROGRESS`, `EMERGENCY_DISABLED`, `POLICY_VERSION_REVOKED`, `POLICY_VERSION_CONFLICT`, `AUTHORIZATION_EXPIRED`, `RESERVATION_STATE_CONFLICT`, `SIGNING_CLAIM_LOST`, `SIGNER_UNAVAILABLE`, `SIGNER_TIMEOUT`, `SIGNER_IDENTITY_MISMATCH`, `INVALID_SIGNATURE`, `STORAGE_UNAVAILABLE`, and `INVALID_INPUT` are separate from Phase 1 policy and Phase 2 admission reasons. They are fixed labels; raw errors are not public reason codes.

## Integration limit

`contracts/AuthorizationReference.sol` proves the digest, signature recovery, and byte encoding against the committed Go vector. `PolicyPaymaster` consumes that same schema and validates actual `PackedUserOperation` fields, sender code hash, `maxCost`, signed validity, and pause state under `BasePaymaster`'s EntryPoint-only boundary. The local E2E bridges durable Go issuance to Solidity validation directly and through Alto. These tests do not reconcile the PostgreSQL hold with a finalized chain outcome.
