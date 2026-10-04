# ADR 003: Database
**Status**: Accepted
**Context**: Local persistence for config lists, blocked attempts, audit.
**Decision**: SQLite with strict tables and append-only SQL migrations; accessed in Phase 1 through Node's built-in `node:sqlite` (no native build step).
**Alternatives**: better-sqlite3 (native build), JSON files (no integrity or querying).
**Consequences**: `node:sqlite` is marked experimental by Node; revisit when the agent language is chosen. The schema is plain SQLite, portable to Rust/C#.
