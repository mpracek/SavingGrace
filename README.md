# SavingGrace

Local, browser-independent protection against adult websites for Windows.
Privacy-first: no telemetry, no cloud, blocked attempts only are logged locally.

## Status

**Phase 3 (Network Protection) is implemented, but the Windows parts have NOT been run on Windows yet.**
The Rust agent runs a local filtering DNS resolver and, on Windows, redirects the system's DNS to it, closes other DNS paths with firewall filters and switches off browsers' own DoH. The DNS filtering is tested on Linux; the Windows enforcement is only type-checked until the CI smoke test has run. There is no Admin UI (Phase 6) or installer (Phase 8).

| Component | Purpose |
|---|---|
| `apps/agent` (Rust) | Windows service, DNS resolver, enforcement, rule engine, SQLite, IPC, logging |

TypeScript libraries (used by the future Admin UI and as a conformance reference):

| Package | Purpose |
|---|---|
| `@savinggrace/shared-types` | Shared TypeScript types |
| `@savinggrace/domain-matcher` | Hostname normalization and label-boundary domain matching |
| `@savinggrace/rule-engine` | Priority-based decisions, global list loader, classifier interface |
| `@savinggrace/configuration` | Strict config parsing with defaults |
| `@savinggrace/database` | SQLite schema, migrations, list/attempt storage |

Roadmap and per-phase reports: `docs/`. See `docs/DEVELOPMENT.md` to build and test.
