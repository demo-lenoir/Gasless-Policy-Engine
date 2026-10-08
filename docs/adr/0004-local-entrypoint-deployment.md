# ADR 0004: local EntryPoint v0.9 deployment identity

Status: Accepted for local integration.

The official [v0.9.0 release](https://github.com/eth-infinitism/account-abstraction/releases/tag/v0.9.0) identifies the v0.9 EntryPoint singleton as `0x433709009B8330FDa32311DF1C2AFA402eD8D009`. The same source tag, commit `b36a1ed52ae00da6f8a4c8d50181e2877e4fa410`, still contains a [deployment artifact named `EntryPoint.json`](https://github.com/eth-infinitism/account-abstraction/blob/v0.9.0/deployments/ethereum/EntryPoint.json) whose address is `0x4337084D9E255Ff0702461CF8895CE9E3b5Ff108`, the v0.8 singleton. The artifact is not evidence that v0.9 was deployed at that address.

The direct integration path compiles `contracts/core/EntryPoint.sol` from the pinned v0.9 source and deploys that contract to a fresh Anvil address. The local address is deployment output, not the canonical singleton address. The local policy snapshot, account, and paymaster use that measured address.

The external-bundler path uses pinned [Alto](https://github.com/pimlicolabs/alto) commit `96529592b67a69be23c013359cbc9990657af64a`, whose v0.9 test fixture submits a deterministic deployment transaction to Anvil. The verifier requires the official v0.9 singleton address to have code and checks its runtime hash against the pinned local fixture value `0x94c969b899cb2a68ac9c124d8ee104a047771ee988f155b4e4683c254291f805`. It records the hash and deployment transaction. Alto identifies v0.9 by that address; a directly deployed arbitrary address cannot exercise its v0.9 RPC path. This fixture is local integration infrastructure, not proof of code on another chain.

Both paths sign their measured EntryPoint identity; no authorization fixture is rewritten to the stale deployment artifact. They prove local interaction with v0.9 implementations. Enabling a nonlocal chain requires independently checking chain ID, address, runtime code hash, and configured interface against trusted deployment evidence.
