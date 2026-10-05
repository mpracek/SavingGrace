# Changelog
## 0.3.0 (Phase 3, 2026-10-04)
- Local filtering DNS resolver (UDP+TCP, loopback only): NXDOMAIN for blocked names and subdomains, CNAME-cloaking check, upstream forwarding with TCP fallback and failover, Firefox DoH canary.
- System enforcement: adapter DNS redirection with persisted originals and tamper repair, WFP firewall filters (DNS only to loopback/agent, DoT and known DoH resolvers blocked), browser DoH-off policies for Chrome, Edge, Brave, Firefox, 5 s watchdog, restore on clean stop.
- `networkFiltering` now reports `not_active` / `dns_only` / `partial` / `enforced`; status adds `dns` and `enforcement`.
- New config keys `dnsEnabled`, `dnsListen`, `dnsUpstreams`, `enforceSystemProtection` (Rust and TypeScript).
- ADR 007 (supersedes ADR 002). Windows smoke test extended. Windows code is type-checked only, not yet run.

## 0.2.0 (Phase 2, 2026-10-04)
- Rust system agent: Windows service with automatic start and crash recovery, data-directory ACL hardening, local IPC (named pipe), strict config loading, SQLite, rule loading, fail-safe degraded modes, daily log files.
- Rust port of matcher/rule engine/config; shared conformance vectors; single SQL schema source.
- `uiLanguage` setting (`sl`/`en`) in both config implementations.
- ADR 001 accepted (Rust), ADR 006 (IPC). CI now builds and tests the agent and runs a Windows service smoke test.
- No network filtering yet.

## 0.1.0 (Phase 1, 2026-10-04)
Foundation: monorepo, shared types, domain matcher, rule engine, configuration, SQLite database, tests, CI, docs.
