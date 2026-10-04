# Security (Phase 2 scope)

## What is tested
- Hostname matching and rule priority; the same vectors pass in TypeScript and Rust.
- Strict config and global-list validation; fail-safe fallbacks (invalid config -> defaults, corrupt DB, missing list).
- IPC hardening: malformed JSON, unknown commands, oversized frames, flooding, stale socket, restart.

## NOT provided yet
**No traffic is intercepted, so no website is blocked.** The status document says so (`networkFiltering: "not_implemented"`).

## Service security (implemented, partly unverified)
- Runs as LocalSystem (needed for later WFP work). Reducing privileges is a Phase 3 item once the required rights are known.
- Plain automatic start (not delayed, to avoid an unprotected window after boot); failure actions restart the service after 5 s, 5 s, 30 s.
- Data directory ACL set to SYSTEM and Administrators only, so ordinary users cannot read the log of blocked attempts or edit the database/config.
- IPC: read-only commands only; named pipe rejects remote clients and refuses to start if the name is already taken.
- **Verified only by compilation on a non-Windows host**: the service code, ACL hardening and named pipe. First real execution is the `scripts/smoke-windows.ps1` CI step.

## Known limitations
- A local administrator can stop or uninstall the service, or edit files. This cannot be prevented from user mode; see the threat model.
- IPC authorization for state-changing commands is undecided (ADR 006) and must be solved before Phase 4/7.
- Logs contain lifecycle events only. Blocked-attempt logging (Phase 5) will be the first privacy-sensitive data.
