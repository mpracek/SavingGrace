# Phase 02 Report: Windows Agent

**Phase**: 2 of 11
**Date**: 2026-10-04

## Decisions
- **Agent language: Rust** (ADR 001, accepted). Reasons: single self-contained executable, memory safety in a LocalSystem service, first-class Windows service and Win32 crates, browser-grade URL parsing (`url` crate).
- Matcher, rule engine, config and global-list loader ported to Rust; kept in sync with the TypeScript versions by shared vectors (`tests/conformance/domain-vectors.json`) and a single SQL schema file.
- IPC (ADR 006): newline-delimited JSON over a named pipe; protocol v1 is read-only.
- User requirements added this phase: Admin UI language choice Slovenian/English (`uiLanguage` setting implemented in config; UI in Phase 6, ADR 004); disable-challenge text taken from the Bible instead of a word list (ADR 005; translation/licence question open for Phase 7).

## Implemented
- Windows service: dispatcher, start/stop/shutdown handling, install/uninstall, automatic start (not delayed), restart-on-failure actions.
- Data-directory ACL hardening (SYSTEM + Administrators only).
- Local IPC server and client with frame limit, connection limit, idle timeout; `ping`, `get_status`, `check_domain`.
- Configuration loading, SQLite with migrations, global list + custom/allow list loading into the rule engine.
- Protection/agent state with fail-safe degraded modes. Honest `networkFiltering: "not_implemented"`.
- Logging foundation: daily rotation, 14 files, lifecycle events only.
- CLI: `run`, `status`, `version`, `install`, `uninstall`, `service`.
- CI: TypeScript job, Rust job on Windows including a service smoke test, Rust tests on Linux.

## Files
Added: `Cargo.toml`, `Cargo.lock`, `apps/agent/**` (15 source files, 2 test files), `packages/database/migrations/0001_initial.sql`, `tests/conformance/*`, `scripts/smoke-windows.ps1`, `docs/adr/006-local-ipc.md`, this report.
Changed: `.github/workflows/ci.yml`, `package.json`, `.gitignore`, shared-types and configuration (`uiLanguage`), configuration tests, ADR 001/004/005, ARCHITECTURE, SECURITY, THREAT_MODEL, DEVELOPMENT, TESTING, ADMIN_GUIDE, INSTALLATION, TROUBLESHOOTING, CHANGELOG, README.

## Tests (executed here, Linux)
| Suite | Count |
|---|---|
| TypeScript (vitest), incl. 66 shared-vector/schema tests | 179 |
| Rust unit tests | 12 |
| Rust conformance (shared vectors) | 4 |
| Rust agent end-to-end over IPC | 9 |
| **Total** | **204, all passing** |

Also executed: `npm run check`, `cargo fmt --check`, `cargo clippy --all-targets -D warnings` (native and Windows target), `cargo build --release`, and a manual run of the release binary (`run` then `status`).
The Rust IPC tests ran 3 times in a row without failure.

## NOT verified (important)
- **Nothing was executed on Windows.** The service, named-pipe transport, ACL hardening and install/uninstall code was only type-checked and linted via cross-compilation (`x86_64-pc-windows-gnu`); behaviour is unverified. The first real run is the `scripts/smoke-windows.ps1` CI step, which has never run. Expect possible fixes after the first CI run.
- The CI workflow itself has never run on GitHub.
- Windows restart / Admin UI restart scenarios (Phase 7).

## Known limitations / security considerations
- No network filtering: the agent blocks nothing. Phase 3 must first verify the Windows approach in ADR 002 against current Microsoft documentation.
- Service runs as LocalSystem; privilege reduction deferred to Phase 3.
- IPC authorization for state-changing commands is undecided (ADR 006) and blocks Phase 4 and 7 work.
- Two matcher implementations must be kept in sync (conformance vectors mitigate this).
- LICENSE is still a placeholder; the seed global list is still a placeholder.

## Documentation updated
ADR 001, 004, 005, 006; ARCHITECTURE; SECURITY; THREAT_MODEL; DEVELOPMENT; TESTING; ADMIN_GUIDE; INSTALLATION; TROUBLESHOOTING; CHANGELOG; README.

## Next phase
Phase 3: Network Protection. Awaiting approval.
