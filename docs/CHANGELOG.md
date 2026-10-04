# Changelog
## 0.2.0 (Phase 2, 2026-10-04)
- Rust system agent: Windows service with automatic start and crash recovery, data-directory ACL hardening, local IPC (named pipe), strict config loading, SQLite, rule loading, fail-safe degraded modes, daily log files.
- Rust port of matcher/rule engine/config; shared conformance vectors; single SQL schema source.
- `uiLanguage` setting (`sl`/`en`) in both config implementations.
- ADR 001 accepted (Rust), ADR 006 (IPC). CI now builds and tests the agent and runs a Windows service smoke test.
- No network filtering yet.

## 0.1.0 (Phase 1, 2026-10-04)
Foundation: monorepo, shared types, domain matcher, rule engine, configuration, SQLite database, tests, CI, docs.
