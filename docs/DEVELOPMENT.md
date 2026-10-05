# Development
Prerequisites: Node.js >= 22.13 and npm (TypeScript packages); Rust >= 1.80 with `clippy` and `rustfmt` (agent).

```text
# TypeScript
npm install
npm run check          typecheck + lint + all tests + build
npm run package        build + npm pack each package into artifacts/

# Rust agent
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo test             unit, conformance, DNS and agent end-to-end tests
cargo build --release  target/release/savinggrace-agent(.exe)
npm run agent:check    the three Rust checks above
```

Run the agent in the foreground (any OS; `--data-dir` is required off Windows):
```text
mkdir -p /tmp/sg/rules && cp data/adult-domains/domains.json /tmp/sg/rules/adult-domains.json
savinggrace-agent run --data-dir /tmp/sg
savinggrace-agent status --data-dir /tmp/sg
```
On Windows, from an elevated prompt, `savinggrace-agent install` registers and starts the service, `uninstall` removes it (data is kept). Both are only exercised by the CI smoke test so far.

Changing matching behaviour: edit `tests/conformance/domain-vectors.json` first, then make both the TypeScript and Rust implementations pass it. Changing the schema: add a new numbered file in `packages/database/migrations/`, a migration entry in both `packages/database/src/migrations.ts` and `apps/agent/src/storage.rs`.

## Working on the DNS/enforcement layer
- Run the resolver on an unprivileged port without touching the system: put `{"dnsListen":["127.0.0.1:5353"],"dnsUpstreams":["9.9.9.9"],"enforceSystemProtection":false}` in `<data-dir>/config.json`, then `dig @127.0.0.1 -p 5353 example.com` (any Unix; `savinggrace-agent run --data-dir <dir>`).
- Enforcement code is written against traits (`SystemDns`, `Firewall`, `PolicyStore`); add tests with fakes first. The Windows backends in `src/enforce/windows/` can only be exercised on Windows (CI smoke test).
- Cross-checking Windows code on Linux (Rust >= 1.80 toolchain with the `x86_64-pc-windows-gnu` target and, for distro toolchains without prebuilt std, `-Zbuild-std`): `cargo clippy --target x86_64-pc-windows-gnu --all-targets -- -D warnings`. This only type-checks; it does not run anything.
