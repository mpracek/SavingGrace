# ADR 001: System agent architecture
**Status**: Accepted (Phase 2)

**Context**: Protection must survive closing the UI and work in every browser, so it needs a Windows service with network-filtering capability. Phase 1 built the matcher and rule engine in TypeScript. The service language was left open.

**Decision**: The agent (`apps/agent`) is written in **Rust**.
- Windows Service via the `windows-service` crate; Win32 (ACLs, and later WFP) via `windows-sys`.
- Single self-contained executable, no runtime to install (simple installer, nothing for a user to uninstall or tamper with besides the exe).
- Memory safety in a component that runs as LocalSystem and parses untrusted hostnames and IPC input.
- Bundled SQLite (`rusqlite`), so no system SQLite dependency.
- `url` crate implements the same WHATWG URL parsing as browsers and Node, which keeps hostname handling consistent.

The matcher, rule engine, configuration and global-list loader were **ported** to Rust. The TypeScript packages remain and are used by the Admin UI (client-side validation) and as a second implementation. They cannot drift unnoticed: `tests/conformance/domain-vectors.json` is run by both the TypeScript tests and the Rust tests, and the SQL schema lives in one file (`packages/database/migrations/*.sql`) that Rust embeds and a TypeScript test compares.

**Alternatives**
- C# / .NET: good Windows APIs, but needs a runtime or a large self-contained bundle, and larger attack surface. Not chosen.
- Node sidecar running the existing TypeScript engine behind a native shim: two processes, a JS runtime inside a LocalSystem service, harder to secure. Not chosen.

**Consequences**: Two implementations of the matching logic must be kept in sync (mitigated by shared vectors). The TypeScript `database` package is no longer the runtime owner of the database; the agent is. The Admin UI will talk to the agent over IPC. The Rust toolchain is required for development.
