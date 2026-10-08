# ADR 0002: canonical sponsorship authorization

Status: Accepted for the issuer and reference verifier.

## Protocol baseline

The integration target is `eth-infinitism/account-abstraction` `v0.9.0`, EntryPoint `0x433709009B8330FDa32311DF1C2AFA402eD8D009`. `PackedUserOperation` has `sender`, `nonce`, `initCode`, `callData`, packed `accountGasLimits`, `preVerificationGas`, packed `gasFees`, `paymasterAndData`, and a separate account signature. The first 52 bytes of `paymasterAndData` are the 20-byte paymaster and two 16-byte paymaster gas limits. The optional suffix is signature bytes, a big-endian two-byte length, and magic `0x22e325a297439656`. The v0.9 hashing helper excludes the signature and its length but retains the magic in its paymaster-data commitment. This issuer uses a dedicated typed authorization to avoid dependence on its own signature bytes.

EntryPoint timestamp validation treats `block.timestamp > validAfter` and `block.timestamp <= validUntil` as valid. The high bit of either `uint48` selects block-number mode; the issuer limits timestamps below `2^47` and uses only timestamp mode. New signing stops at `now >= validUntil`, a conservative boundary. The reference verifier does not implement EntryPoint validation.

Sources: [PackedUserOperation](https://github.com/eth-infinitism/account-abstraction/blob/v0.9.0/contracts/interfaces/PackedUserOperation.sol), [UserOperationLib](https://github.com/eth-infinitism/account-abstraction/blob/v0.9.0/contracts/core/UserOperationLib.sol), [Helpers](https://github.com/eth-infinitism/account-abstraction/blob/v0.9.0/contracts/core/Helpers.sol), [EntryPoint](https://github.com/eth-infinitism/account-abstraction/blob/v0.9.0/contracts/core/EntryPoint.sol), [IPaymaster](https://github.com/eth-infinitism/account-abstraction/blob/v0.9.0/contracts/interfaces/IPaymaster.sol), [BasePaymaster](https://github.com/eth-infinitism/account-abstraction/blob/v0.9.0/contracts/core/BasePaymaster.sol).

## Domain and struct

EIP-712 domain: `EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)`, with name `GaslessPolicyEngine`, schema version `1`, admitted chain ID, and verifying contract equal to the paymaster. Policy version is business data in the struct. The signed type string and order are fixed in `internal/authorization` and `contracts/AuthorizationReference.sol`:

```text
Sponsorship(bytes32 sponsorshipId,uint64 policyVersion,bytes32 policyHash,address entryPoint,address sender,bytes32 accountCodeHash,uint256 nonce,bytes32 initCodeHash,bytes32 callDataHash,bytes32 accountGasLimits,uint256 preVerificationGas,bytes32 gasFees,uint128 paymasterVerificationGasLimit,uint128 paymasterPostOpGasLimit,uint256 maxSponsorCostWei,uint48 validAfter,uint48 validUntil)
```

`sponsorshipId` is the reservation's exact 32 database bytes. `policyHash` is SHA-256 of the published canonical static, accounting, and issuance-profile configuration; it identifies the original approval snapshot. Admission persists the immutable issuance profile with the request, binding one policy version and chain ID to one paymaster, EntryPoint, fixed-account runtime code hash, and signer address. Issuance only reads and verifies this profile. A changed profile requires a new policy version; a reservation admitted without one is ineligible for signing. The fixed-account flow has empty `initCode`; its signed hash is `keccak256("")`. `callDataHash` covers the entire canonical `execute(address,uint256,bytes)` encoding. The target, inner selector, inner calldata, and call value are bound through that hash without separately signed metadata. `PolicyPaymaster` checks the sender's code hash and actual operation fields. Account signature bytes are outside the sponsor digest and remain subject to account validation.

`accountGasLimits` and `gasFees` preserve the v0.9 `uint128 || uint128` order. `maxSponsorCostWei` equals the committed reservation amount: `(callGasLimit + verificationGasLimit + preVerificationGas + paymasterVerificationGasLimit + paymasterPostOpGasLimit) * maxFeePerGas`, using checked uint256 arithmetic. `PolicyPaymaster` rejects `maxCost > maxSponsorCostWei`. This is an admission upper bound, not observed expenditure. Call value is funded by the account, not the gas sponsor.

Changing chain ID, paymaster, EntryPoint, sender, account code identity, nonce, `initCode`, any account calldata byte, any signed gas or fee field, policy version or hash, sponsorship ID, cost cap, or either validity timestamp changes the digest. Go and Solidity use the same committed vector and mutation tests.

## Wire format and signature

`paymasterData` is exactly 116 bytes: `sponsorshipId[32] || policyVersion[8] || policyHash[32] || maxSponsorCostWei[32] || validAfter[6] || validUntil[6]`; integers are big-endian. Full `paymasterAndData` is 243 bytes: `paymaster[20] || verificationGas[16] || postOpGas[16] || paymasterData[116] || signature[65] || uint16(65)[2] || magic[8]`. The signature is secp256k1 `r[32] || s[32] || v[1]`, with low `s` and `v` in `{27,28}`. Go converts the local signer's recovery bit from 0/1 to 27/28, then validates length, range, low `s`, and recovered address before commit. The Solidity paymaster applies the same rules and rejects extra bytes.

The issuer constructs the digest from durable admitted data. No client digest reaches `SponsorSigner`. A short transaction assigns a fenced signing lease; signer I/O occurs outside PostgreSQL; a final transaction rechecks status, validity, emergency disable, policy revocation, claim generation, and absence of an artifact before committing one immutable artifact and its audit event. Already committed artifacts are returned byte-for-byte on retry. A signature lost before commit can be recreated for the same digest and sponsorship ID.

## Replay and revocation boundary

The EntryPoint account nonce is the on-chain replay control: after inclusion, the same nonce cannot validate again on the canonical chain. `sponsorshipId` is an off-chain uniqueness and audit identifier, not an on-chain spent-ID map. Reorganization can reopen a nonce before finality; outcome reconciliation is deferred. Emergency disable prevents new artifact commits but cannot revoke already issued artifacts. The paymaster owner's on-chain pause stops outstanding valid signatures after its transaction lands. Phase 4 direct and external-bundler tests prove exact replay rejection on local Anvil.

Signed reservations remain economically held after validity until confirmed chain outcome reconciliation establishes whether they were spent or expired unused. A bounded worker records elapsed `AUTHORIZATION_EXPIRED` after `validUntil` without returning Wei. The Phase 5 reconciler releases unused capacity only after confirmed canonical scan coverage past the validity deadline.

## Change from the earlier design

The earlier semantic list included separately signed target, inner calldata hash, and call value. The implemented struct omits these redundant fields because the full canonical outer account calldata hash commits them, and the paymaster recomputes that hash directly from `PackedUserOperation`. Target and selector remain policy inputs and audit metadata. Schema version `1` is the first implemented wire format; later wire changes require a new schema version and vectors.
