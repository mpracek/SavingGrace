# Architecture (as implemented in Phase 2)

SavingGrace is a system-level agent, not a browser extension. What exists today:

```text
                 +--------------------------------------------+
                 |  savinggrace-agent (Rust, apps/agent)       |
 Windows SCM --> |  Windows service "SavingGrace" (auto start) |
 CLI/`run` ----> |                                            |
                 |  config -> storage (SQLite) -> rules       |
                 |  global list file                          |
                 |  state (running / degraded / stopping)     |
                 |  IPC server (named pipe, read-only cmds)   |
                 +--------------------------------------------+
                          ^ JSON lines
                          |
                 Admin UI / `savinggrace-agent status`   (UI not built yet)
```

**Network filtering does not exist yet (Phase 3).** The agent therefore reports `networkFiltering: "not_implemented"` and never claims protection is active.

## Components
| Module | Role |
|---|---|
| `domain` | Hostname normalization and label-boundary matching (port of the TS matcher) |
| `rules` | Fixed priority allowlist > custom > global > default; global list parser |
| `config` | Strict parsing; unknown keys / out-of-range values rejected |
| `storage` | SQLite, append-only migrations from `packages/database/migrations/` |
| `state` | `AgentState` (starting/running/degraded/stopping) and the status document |
| `ipc` | Newline-delimited JSON server and client; named pipe (Windows) / Unix socket (dev) |
| `logging` | Daily-rotated file log (14 kept), lifecycle events only, no hostnames |
| `service_windows` | Service dispatcher, stop/shutdown handling, install/uninstall, recovery actions |
| `security_windows` | Protected DACL on the data directory (SYSTEM and Administrators only) |

## Startup sequence and fail-safe policy (tested)
1. Create the data directory; on Windows restrict its ACL.
2. Load `config.json`. Invalid -> **built-in strict defaults** + degraded.
3. Open the database and read the allowlist and custom blocklist. Failure -> lists empty + degraded.
4. Load `rules/adult-domains.json`. Missing or invalid -> no global list + degraded.
5. Build the immutable rule engine.
6. Bind the IPC endpoint. This is the only failure that stops the agent.
7. Service reports RUNNING.

A component that fails to load never stops the others, and is always visible as a degraded reason in `get_status`.

## Data directory (`%ProgramData%\SavingGrace`)
`config.json`, `savinggrace.sqlite`, `rules/adult-domains.json`, `logs/agent.<date>.log`.

## Rule evaluation
```text
normalize hostname -> allowlist (ALLOW) -> custom blocklist (BLOCK) -> global blocklist (BLOCK) -> default ALLOW
```
Classifiers exist as an interface in the TypeScript engine only; the agent has none until Phase 11.

## Not yet implemented
Network filtering, list editing over IPC, attempt logging and statistics, Admin UI (with Slovenian/English language choice), temporary disable and its Bible-text challenge, installer, rule updates.
