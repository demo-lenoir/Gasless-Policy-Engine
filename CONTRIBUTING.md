# Contributing

Keep changes scoped to the current phase and update the specification or ADR when a security invariant changes. Use concise commit subjects such as `docs: clarify reservation expiry` or `build: strengthen phase0 checks`.

Run `make verify-phase2` for current changes; it includes earlier gates and real PostgreSQL integration tests. Add tests at the relevant trust boundary. Do not commit keys, seed phrases, local credentials, deployment secrets, or machine-specific paths. Report suspected security issues privately as described in [SECURITY.md](SECURITY.md).
