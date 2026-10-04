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
cargo test             unit, conformance and IPC end-to-end tests
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
