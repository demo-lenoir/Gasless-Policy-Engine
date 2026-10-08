# ADR 0001: ERC-4337 integration baseline

Status: Accepted integration baseline; contract and bundler dependencies pinned.

## Decision

Use the official `eth-infinitism/account-abstraction` `v0.9.0` contracts and EntryPoint interface. Its release identifies EntryPoint `0x433709009B8330FDa32311DF1C2AFA402eD8D009`. Use `PackedUserOperation` and the v0.9 paymaster signature suffix. Use a fixed single-call project account and project paymaster against this EntryPoint. Do not use a v0.6/v0.7 tutorial paymaster or assume the v0.8 address.

Account-abstraction `v0.9.0` remains a Git submodule at `b36a1ed52ae00da6f8a4c8d50181e2877e4fa410`. OpenZeppelin Contracts `v5.7.0` and the separate Alto bundler use checksum-checked local source snapshots; `dependency-snapshots/manifest.json` records their upstream commits, snapshot commits, and bundle hashes. Executable source and nested dependency revisions match the upstream commits; upstream Markdown is omitted. Compile with Solidity `0.8.37`; the verified local Foundry/Anvil version is `v1.8.4-Homebrew`. Go uses go-ethereum `v1.17.7` with Go `1.27.1`. Alto is built with its locked pnpm `8.15.4` dependencies. Its v0.9 support is verified by a local `eth_sendUserOperation` integration, not inferred solely from a README.

| Phase 2 dependency | Pinned version | Use |
| --- | --- | --- |
| `github.com/jackc/pgx/v5` | `v5.11.0` | PostgreSQL transactions and connection pool. |
| `github.com/prometheus/client_golang` | `v1.24.1` | Bounded-label admission and lifecycle metrics. |
| `github.com/ethereum/go-ethereum` | `v1.17.7` | Keccak and secp256k1 operations in the authorization and development signer. |

The upstream `BasePaymaster` constructor takes the EntryPoint and owner; it checks `IEntryPoint` interface support. `IPaymaster.validatePaymasterUserOp(PackedUserOperation,bytes32,uint256)` returns context and validation data, and `postOp` includes actual gas cost and fee per gas. `PackedUserOperation.paymasterAndData` starts with a 20-byte paymaster, two 16-byte gas limits, then paymaster data. Its optional signature suffix is signature bytes, a 2-byte length, and magic `0x22e325a297439656`. The signature bytes are excluded from EntryPoint's UserOperation hash. V1 uses timestamp validity and rejects v0.9 block-number validity flags.

## Compatibility and deployment checks

The account-abstraction source uses Solidity `^0.8.28`; OpenZeppelin's EIP-712 source uses `^0.8.24`, so `0.8.37` satisfies both. The go-ethereum `v1.17.7` module declares Go `1.25.0`, satisfied by `1.27.1`. A future deployment must check chain ID, EntryPoint address, runtime code hash, supported interface, bundler support, and expected hardfork features before enabling a chain. A known address alone is insufficient proof of correct code.

## Deviation from older integration patterns

Earlier guidance often binds the whole `paymasterAndData` into `userOpHash`, creating a signature dependency cycle or requiring the account to sign last. V0.9's suffix removes that dependency. We use it but still define a separate paymaster EIP-712 struct with an explicit EntryPoint binding and full operation commitment. The account signature and sponsor signature remain separate.

## Upstream evidence

- [Account-abstraction v0.9.0 release](https://github.com/eth-infinitism/account-abstraction/releases/tag/v0.9.0)
- [v0.9 `PackedUserOperation`](https://github.com/eth-infinitism/account-abstraction/blob/v0.9.0/contracts/interfaces/PackedUserOperation.sol)
- [v0.9 `IPaymaster`](https://github.com/eth-infinitism/account-abstraction/blob/v0.9.0/contracts/interfaces/IPaymaster.sol)
- [v0.9 `BasePaymaster`](https://github.com/eth-infinitism/account-abstraction/blob/v0.9.0/contracts/core/BasePaymaster.sol)
- [v0.9 `UserOperationLib`](https://github.com/eth-infinitism/account-abstraction/blob/v0.9.0/contracts/core/UserOperationLib.sol)
- [v0.9 `Helpers`](https://github.com/eth-infinitism/account-abstraction/blob/v0.9.0/contracts/core/Helpers.sol)
- [v0.9 `EntryPoint`](https://github.com/eth-infinitism/account-abstraction/blob/v0.9.0/contracts/core/EntryPoint.sol)
- [Paymaster signature format](https://docs.erc4337.io/paymasters/paymaster-signature.html)
- [OpenZeppelin Contracts releases](https://github.com/OpenZeppelin/openzeppelin-contracts/releases/tag/v5.7.0)
- [OpenZeppelin EIP-712 source](https://github.com/OpenZeppelin/openzeppelin-contracts/blob/v5.7.0/contracts/utils/cryptography/EIP712.sol)
- [Solidity v0.8.37](https://github.com/ethereum/solidity/releases/tag/v0.8.37)
- [Foundry v1.8.5](https://github.com/foundry-rs/foundry/releases/tag/v1.8.5)
- [go-ethereum v1.17.7](https://github.com/ethereum/go-ethereum/releases/tag/v1.17.7) and [module requirement](https://github.com/ethereum/go-ethereum/blob/v1.17.7/go.mod)
- [pgx v5 changelog](https://github.com/jackc/pgx/blob/master/CHANGELOG.md) and [pgxpool documentation](https://pkg.go.dev/github.com/jackc/pgx/v5/pgxpool)
- [Prometheus Go client v1.24.1](https://github.com/prometheus/client_golang/releases/tag/v1.24.1)
- [ERC-7562 validation scope rules](https://eips.ethereum.org/EIPS/eip-7562)
- [Pinned Alto source with v0.9 RPC and E2E coverage](https://github.com/pimlicolabs/alto/tree/96529592b67a69be23c013359cbc9990657af64a)
