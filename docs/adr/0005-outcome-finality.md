# ADR 0005: finalized EntryPoint evidence owns settlement

## Decision

Use `UserOperationEvent` from the configured v0.9 EntryPoint as the cost and outcome authority. Bind each issued authorization to the supported operation's `userOpHash` when the artifact commits. Keep fork observations separate from the Phase 2 economic reservation state. Process HTTP block and log ranges from a durable checkpoint. Local settlement uses three confirmations and automatic reorg recovery up to eight blocks.

An observed operation keeps its reservation held until the event is canonical at the confirmation threshold. Its `actualGasCost` consumes the original admission-period capacity regardless of the target execution result. Unused signed capacity returns only after the same confirmed scan watermark has a canonical timestamp strictly beyond `validUntil` and no canonical event exists.

The stream checkpoint is locked before reservation rows. One active stream per chain avoids conflicting canonical projections; old issued profiles must settle before stream rotation. Terminal economic accounting is not automatically reversed. An overage, conflicting evidence, deep reorg, or post-settlement contradiction stops automatic settlement and requires operator review.

## Reasons

Bundler responses do not establish inclusion or cost. A shallow event can disappear under reorg. Host time alone cannot prove that a still-valid operation was absent from the chain. The checkpoint plus canonical block history connects an empty scan to a specific confirmed chain-time watermark. Keeping the original budget period prevents a delayed finality boundary from moving spend into a different allowance.

## Consequences

Holds can remain unavailable during RPC outages or an unresolved fork. Three confirmations are only a local reference threshold. The reader remains a trust assumption for log completeness and chain identity. Manual intervention is required when terminal accounting conflicts with later canonical evidence. See [reconciliation contract](../reconciliation.md) and [failure matrix](../failure-matrix.md).
