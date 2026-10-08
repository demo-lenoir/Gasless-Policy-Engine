# EntryPoint outcome reconciliation

## Evidence and identity

The pinned account-abstraction v0.9.0 `IEntryPoint.UserOperationEvent` emits indexed `userOpHash`, `sender`, and `paymaster`, followed by `nonce`, `success`, `actualGasCost`, and `actualGasUsed`. The event is the inclusion, execution-result, and sponsor-cost evidence. `UserOperationRevertReason` is diagnostic and is not the settlement authority. An account call that reverts still emits `UserOperationEvent(success=false)` and consumes sponsor gas.

`internal/userop.Hash` reproduces the pinned `EntryPoint.getUserOpHash` for the fixed deployed-account flow. Its typed operation hash covers sender, nonce, empty `initCode`, complete account calldata, account gas limits, pre-verification gas, fees, and paymaster data. V0.9 excludes the account signature and the paymaster signature suffix; the paymaster-data hash retains the eight-byte suffix magic. The `ERC4337` EIP-712 domain includes chain ID and EntryPoint. The local chain gate compares this hash against `getUserOpHash` before account signing. Authorization commit stores `user_op_hash` atomically with the immutable signed artifact. The sponsorship ID remains the off-chain accounting ID; EntryPoint/account nonce validation prevents canonical replay.

The watcher filters only the configured EntryPoint's `UserOperationEvent` with the configured paymaster topic. It checks the decoded EntryPoint, paymaster, userOp hash, sender, nonce, chain scope, block hash/number, and transaction/log identity before correlating an observation. A different paymaster, EntryPoint, or chain cannot settle a reservation.

## Scanning and canonicality

HTTP `HeaderByNumber` and `FilterLogs` calls are the completeness path. A stream starts at block zero and advances through bounded contiguous blocks; startup verifies chain ID, EntryPoint code, and a readable head. RPC work stays outside PostgreSQL transactions. The stream checkpoint is keyed by chain ID, EntryPoint, and stream ID. Each block transaction stores `(chain ID, block hash)` ancestry and observations, updates provisional outcome state, then advances the checkpoint. A checkpoint therefore means every filtered event through that height was represented. Repeated block fetches are idempotent. Competing hashes at the same height coexist in history, with one canonical projection.

Before catch-up, a worker compares its durable checkpoint hash to the current chain header. It rolls back a differing branch only when it finds a stored common ancestor within the configured depth. Observations on orphaned blocks remain in the database with `canonical=false`; affected unresolved reservations return to `REORGED` and keep their hold. If no ancestor is found, or an already terminal settlement is contradicted, the stream enters `MANUAL_INTERVENTION` and stops advancing. Local reference settings are three confirmations and an eight-block automatic reorg bound. These are test policy values, not universal Ethereum finality.

Multiple workers serialize on the checkpoint row. Settlement locks the checkpoint, then a bounded batch of reservations, then all-chain, chain, and sender budget rows. The same order is used by block application and reorg handling. PostgreSQL locks and uniqueness constraints prevent duplicate observations and economic transitions; no process-local mutex is required. A restart resumes from the committed checkpoint, including after a lost submission response. V1 permits one active reconciliation stream per chain; settlement filters reservations by its EntryPoint and paymaster profile. Profile rotation requires all old authorizations to settle and an explicit operator migration of checkpoint identity; automatic rotation is not implemented.

## Finality and economic settlement

For a canonical event at height `E` and scanned head `H`, confirmations are `H - E + 1`. At the configured threshold, the event may become `FINAL`. Before then, `OBSERVED` or `CONFIRMING` leaves the reservation `RESERVED`. The event's exact integer `actualGasCost` is authoritative; target-call `success` is stored separately and does not decide whether gas was spent.

One PostgreSQL transaction sets `FINAL`, moves the original admission-period hold to actual consumed Wei, inserts one `actual_spend_ledger` row, and appends audit events. For a normal consumed reservation, `reserved_wei = actual_wei + released_wei`. The released amount is the unused hold. The sender admission count remains charged. Settlement never reassigns spend to the date of on-chain execution or finality.

If actual cost exceeds the reserved upper bound, the full observed amount is retained, the hold is not released, and a durable anomaly places the stream and reservation in manual intervention. Terminal accounting is not silently reversed after a deeper reorg; that contradiction likewise requires manual reconciliation.

An unused signed authorization expires economically only when the supplied observation time and a canonical, completely scanned, sufficiently confirmed block timestamp are both strictly later than `validUntil`, with no canonical event and no unresolved anomaly. EntryPoint timestamp validity includes `validUntil`, so equality cannot release a hold. Expiry returns the original hold exactly once and retains the sender admission count. Bundler acceptance, rejection, timeout, or missing response never settles a hold by itself.

## Limits

The trusted RPC reader can omit logs or present a stale head; polling and durable catch-up do not cryptographically prove absence. A deployment must choose a reader and finality policy appropriate to its chain and monitor lag and anomalies. A reorg beyond the configured bound stops automatic work. Production RPC redundancy, operator resync tooling, and public readiness exposure remain outside this local reference implementation.
