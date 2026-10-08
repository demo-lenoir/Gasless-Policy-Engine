# Gasless Policy Engine

A security-focused ERC-4337 sponsorship backend in Go.

A product can sponsor account operations so users need no native gas token. Unrestricted sponsorship exposes the paymaster deposit to unsupported calls, replay, gas inflation, and budget exhaustion. The service derives the target and selector from fixed-account calldata, applies versioned policy, atomically reserves quota and Wei capacity, and issues an EIP-712 authorization for one operation. EntryPoint v0.9 and the paymaster enforce the signed constraints. A PostgreSQL-backed watcher settles confirmed `UserOperationEvent.actualGasCost` and releases unused capacity.

## Local demo

With Go 1.27.1, PostgreSQL 18.6 command-line tools, Python 3, Ruby, ripgrep, Foundry/Anvil 1.8.4, Node.js, pnpm, and Docker available:

```sh
python3 scripts/prepare_dependencies.py
make demo
```

Set `LOCAL_NODE_BIN` if Node.js is outside `PATH`. The command creates disposable PostgreSQL and Anvil instances, deploys the pinned EntryPoint/paymaster/account/target, starts Alto, and calls the real sponsorship HTTP handler. It checks `APPROVED`, durable artifact recovery on retry, an idempotency conflict, a policy denial, zero account gas balance, a mutated-call rejection, Alto inclusion, `CONSUMED`, exact `actualGasCost`, and unused hold release. A second signed authorization is never submitted and moves from `RESERVED` to `EXPIRED` only after confirmed chain-time coverage. The command prints a SHA-256 accounting checksum and writes ignored local metadata to `build/local-deployment.json`.

`make verify-phase6` is the authoritative local gate. It includes the earlier phase gates, race-enabled Go and Foundry tests, fresh PostgreSQL migrations, direct and Alto execution, reconciliation, the complete demo, vulnerability and image scans, a clean-clone run, Docker build/runtime smoke, and unsigned local release artifacts. The optional local service command is `go run ./cmd/gasless`; it requires a runtime policy file, admission file with one issuance profile, PostgreSQL and RPC URLs, a scoped bearer token, and a development signer key supplied through environment variables. See the [API contract](api/openapi.yaml) and [operations runbook](docs/operations.md). This reference process accepts a development signer only and binds to loopback unless explicitly overridden for an isolated container network.

## Design and evidence

- [Specification](SPEC.md), [architecture](docs/architecture.md), and [threat model](docs/threat-model.md)
- [Policy rules](docs/policy.md), [accounting](docs/accounting.md), and [authorization issuance](docs/signing.md)
- [Outcome reconciliation](docs/reconciliation.md), [failure matrix](docs/failure-matrix.md), and [observability](docs/observability.md)
- [Test evidence](docs/evidence.md), [local demo](docs/demo.md), and [release procedure](docs/release.md)
- [Signing](docs/adr/0002-sponsorship-signing.md), [budget](docs/adr/0003-budget-reservations.md), [local deployment](docs/adr/0004-local-entrypoint-deployment.md), and [finality](docs/adr/0005-outcome-finality.md) decisions

Account-abstraction remains pinned at `b36a1ed52ae00da6f8a4c8d50181e2877e4fa410`. Alto and OpenZeppelin are loaded from the complete, checksum-checked bundles in `dependency-snapshots/`; [the manifest](dependency-snapshots/manifest.json) records their upstream and local snapshot commits. Only upstream Markdown was omitted from those two snapshots; executable source and nested dependency revisions were retained. The setup command fetches each nested dependency at its exact pinned commit with a one-commit shallow history. Clone this repository without `--recurse-submodules`, then run the setup command above. Solidity is pinned to 0.8.37; the local Foundry/Anvil fixture uses 1.8.4.

The PostgreSQL budget is an authorization limit; the EntryPoint deposit is the on-chain gas source. RPC log completeness is trusted, not cryptographically proven. The configured confirmation count is not universal finality. The local Alto run does not establish production ERC-7562 mempool acceptance. Development keys are test-only; production key custody is outside this implementation. There is no production history, independent audit, or testnet/mainnet deployment evidence.

Apache-2.0. See [LICENSE](LICENSE).
