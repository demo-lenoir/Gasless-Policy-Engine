# Security policy

This repository contains a policy and accounting core, a development signer, a local HTTP service, durable authorization issuance, an EntryPoint-facing paymaster/account integration, and outcome reconciliation. The tested chain and bundler are local fixtures. Do not use the development signer or deterministic local keys to sponsor real funds.

For a suspected vulnerability, contact the repository owner privately before opening a public issue. No dedicated disclosure address has been selected. Include the affected design or code path, impact, and a minimal reproduction when available. Avoid sending seed phrases, private keys, or live credentials.

The [threat model](docs/threat-model.md) lists expected controls and residual assumptions. RPC completeness remains a trust assumption; a configured confirmation count does not establish universal finality. The local Alto run does not prove production ERC-7562 mempool acceptance. Production key custody, public-chain deployment, and incident-response integrations are outside this implementation. No production history or independent audit is claimed.
