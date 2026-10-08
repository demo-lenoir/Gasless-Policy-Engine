# Static policy behavior

`internal/policy` is a side-effect-free Go package. `Normalize` accepts canonical decimal strings for Ethereum quantities and hex calldata, canonicalizes addresses to lowercase bytes, and parses the fixed account's `execute(address,uint256,bytes)` ABI (`0xb61d27f6`). It requires the exact canonical ABI layout, one nonzero target, at least four inner calldata bytes, zero padding, and no trailing bytes. Batch calls, `executeUserOp`, deployment `initCode`, EIP-7702, arbitrary account ABIs, fallback, and receive are outside the accepted request shape. The target, value, selector, and inner calldata come from this decoded call; the request has no separate trusted target or selector field. An allowed selector does not constrain its arguments or downstream calls made by the target.

`NewSnapshot` or `ReadSnapshotJSON` validates the full configuration before use. A snapshot owns private maps and does not retain caller slices. Targets and selectors are scoped to a chain; each chain also pins an EntryPoint address. Reordered allow/deny lists have the same semantics. Duplicate selector and denylist values collapse to sets; duplicate chain or target rules are rejected. A target may appear in both allow and deny lists so an emergency target deny overrides the allowlist. The [example policy](../config/policy.example.json) uses no credentials.

## Reason precedence

`EvaluateRaw` checks snapshot validity, then emergency disable, then normalization. A malformed or unsupported call is denied before static rules. For normalized requests, `Evaluate` checks, in order:

1. Chain allowlist and configured EntryPoint address.
2. Sender denylist.
3. Target denylist, target allowlist, then target-scoped selector allowlist.
4. Call value.
5. Call gas, account verification gas, pre-verification gas, paymaster verification gas, then post-operation gas.
6. Max fee per gas, then max priority fee per gas and its relation to max fee.
7. Estimated sponsor cost cap.
8. Requested or default validity duration and explicit evaluation time.

The first failing rule determines the stable reason. The v1 post-operation gas cap is zero. A malformed policy cannot be evaluated. The Go package does not read a clock, environment variable, RPC endpoint, database, or key.

## Quantities and cost

All Ethereum quantities are checked uint256 values represented as fixed 32-byte values. Decimal input has no sign or leading zero. Gas and fee fields above EntryPoint v0.9's `uint120` validation bound are rejected during normalization. The policy caps call gas, verification gas, pre-verification gas, paymaster verification gas, post-operation gas, max fee, and priority fee independently. `EstimatedUpperBound` computes:

```text
(callGas + verificationGas + preVerificationGas
 + paymasterVerificationGas + paymasterPostOpGas) * maxFeePerGas
```

This matches the [v0.9 EntryPoint required-prefund field set](https://github.com/eth-infinitism/account-abstraction/blob/v0.9.0/contracts/core/EntryPoint.sol) and uses checked arithmetic. It is an admission upper bound, not an actual-spend report. Sponsor budgets are not consumed in Phase 1.

## Validity

A client may request a duration in seconds, not absolute timestamps. The example policy accepts 10 through 120 seconds and defaults to 60. The constructor rejects maximums above five minutes. Out-of-range requests are denied without clamping. `EvaluationContext.Now` supplies time; valid-after and valid-until are UTC second timestamps and must stay below v0.9's block-number validity flag.
