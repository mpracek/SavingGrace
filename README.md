# SavingGrace

Local, browser-independent protection against adult websites for Windows.
Privacy-first: no telemetry, no cloud, blocked attempts only are logged locally.

## Status

**Phase 2 (Windows Agent) is complete. SavingGrace does NOT block anything yet.**
The Rust agent runs as a Windows service with local IPC, but there is no network filtering (Phase 3) and no Admin UI (Phase 6).

| Component | Purpose |
|---|---|
| `apps/agent` (Rust) | Windows service, rule engine, SQLite, IPC, logging |

TypeScript libraries (used by the future Admin UI and as a conformance reference):

| Package | Purpose |
|---|---|
| `@savinggrace/shared-types` | Shared TypeScript types |
| `@savinggrace/domain-matcher` | Hostname normalization and label-boundary domain matching |
| `@savinggrace/rule-engine` | Priority-based decisions, global list loader, classifier interface |
| `@savinggrace/configuration` | Strict config parsing with defaults |
| `@savinggrace/database` | SQLite schema, migrations, list/attempt storage |

Roadmap and per-phase reports: `docs/`. See `docs/DEVELOPMENT.md` to build and test.
