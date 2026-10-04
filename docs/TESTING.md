# Testing
- **TypeScript (vitest, `tests/`)**: domain-matching, rule-engine, configuration, database, integration, conformance (shared vectors + SQL schema equality).
- **Rust (`cargo test`)**: unit tests in `src/`, `tests/conformance.rs` (shared vectors), `tests/agent_ipc.rs` (boots the real agent in a temp dir and talks to it: healthy boot, rule priority from disk, degraded modes, protocol abuse, shutdown/restart, stale socket).
- **Windows**: `scripts/smoke-windows.ps1` (CI): install, auto-start mode, status over the named pipe, data-dir ACL, kill and restart, uninstall. The named-pipe and service code is not covered by any other test.
- Not covered yet: network and browser tests (Phase 3), challenge tests (Phase 7), Windows restart / UI restart (Phase 7).
