# Phase 01 Report: Foundation

**Phase**: 1 of 11 (Foundation)
**Date**: 2026-10-04

## Implemented features
- npm-workspaces monorepo (TypeScript strict, vitest, eslint, tsc project references)
- `shared-types`, `domain-matcher`, `rule-engine`, `configuration`, `database` packages
- Global adult-domain list loader/validator (v1 and v2 schema) and a small **seed** list (8 well-known domains, `data/adult-domains/domains.json`). It is a placeholder dataset, not a production list; a vetted source is a Phase 4 task.
- SQLite schema v1 with migrations (settings, custom_blocklist, allowlist, access_attempts, disable_audit)
- Classifier interface in the rule engine (no classifiers shipped)
- CI workflow, architecture/security/threat-model docs, ADR 001-005

## Not implemented (by design, later phases)
Windows service, IPC, network filtering, Admin UI, installer, rule updates, challenge logic, statistics/retention queries, `logging` package. **No blocking of any website happens yet.**

## Tests
| Area | Tests |
|---|---|
| domain-matching | 57 |
| rule-engine (incl. global list parsing) | 27 |
| configuration | 19 |
| database | 6 |
| integration | 2 |
| **Total** | **111, all passing** |

## Checks executed (in this environment, Linux, Node 22.22)
`npm run typecheck`, `npm run lint`, `npm test`, `npm run build`, `npm run package`, all exit 0. `npm run check` exit 0.

## Not verified
- CI on GitHub Actions (workflow written for windows-latest, never run).
- Anything on Windows itself. Development and tests ran on Linux.
- The Windows networking approach in ADR 002 is from general knowledge and has NOT been checked against current Microsoft documentation. That check gates Phase 3.

## Known limitations / security considerations
- `node:sqlite` is experimental in Node (ExperimentalWarning in test output).
- Invalid hostnames are allowed by default (`onInvalidInput`).
- LICENSE is a placeholder; the owner must choose a license.
- The agent language question (TypeScript core vs native Rust/C# agent) is open (ADR 001) and must be settled first in Phase 2.

## Documentation updated
README, docs/architecture, security, threat-model, adr/001-005, user-guide (honest stubs), DEVELOPMENT, TESTING, TROUBLESHOOTING, CHANGELOG.

## Next phase
Phase 2: Windows Agent. Awaiting approval.
