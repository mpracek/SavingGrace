# Architecture (as implemented in Phase 3)

SavingGrace is a system-level agent, not a browser extension. What exists today:

```text
                 +--------------------------------------------+
                 |  savinggrace-agent (Rust, apps/agent)       |
 Windows SCM --> |  Windows service "SavingGrace" (auto start) |
 CLI/`run` ----> |                                            |
                 |  config -> storage (SQLite) -> rules       |
                 |  global list file                          |
                 |  DNS resolver 127.0.0.1:53 / [::1]:53      |
                 |  enforcement: adapter DNS + WFP + policies |
                 |  watchdog (5 s)                            |
                 |  state (running / degraded / stopping)     |
                 |  IPC server (named pipe, read-only cmds)   |
                 +--------------------------------------------+
                          ^ JSON lines
                          |
                 Admin UI / `savinggrace-agent status`   (UI not built yet)
```

**Filtering works at the DNS level (ADR 007).** The agent runs a loopback resolver, redirects the system's DNS to it, and uses firewall filters and browser policies so nothing else can resolve names. `networkFiltering` reports what is actually true: `not_active`, `dns_only`, `partial` or `enforced`.

## Components
| Module | Role |
|---|---|
| `domain` | Hostname normalization and label-boundary matching (port of the TS matcher) |
| `rules` | Fixed priority allowlist > custom > global > default; global list parser; `evaluate_dns_name` (no URL parsing) |
| `config` | Strict parsing; unknown keys / out-of-range values rejected; DNS keys validated (loopback listeners only) |
| `storage` | SQLite, append-only migrations from `packages/database/migrations/` |
| `dns::filter` | Decision per DNS packet: NXDOMAIN, forward, CNAME-cloaking check, FORMERR/SERVFAIL handling |
| `dns::upstream` | Forwarding over UDP with TCP fallback, failover across servers, transaction-id check |
| `dns::server` | UDP and TCP listeners, concurrency limits, loopback only |
| `enforce::dns_redirect` | Adapter DNS redirection with persisted originals, tamper detection, upstream discovery |
| `enforce::firewall` | Declarative filter list (permit loopback/agent DNS, block other DNS, DoT, known DoH IPs) |
| `enforce::browser_policy` | DoH-off policies for Chrome, Edge, Brave, Firefox with prior values recorded |
| `enforce::store` | Persistent record of everything changed, so it can be undone |
| `enforce` | `Enforcer`: ordering rules and status; `PlatformEnforcer` trait |
| `enforce::windows` | IP Helper, WFP (dynamic session) and registry backends |
| `state` | `AgentState`, `FilteringStatus`, status document |
| `ipc` | Newline-delimited JSON; named pipe (Windows) / Unix socket (dev); read-only commands |
| `logging` | Daily-rotated file log, lifecycle events only, no hostnames |
| `service_windows`, `security_windows` | Service control, install/uninstall, data-dir ACL |

## Startup sequence and fail-safe policy (tested)
1. Create the data directory; on Windows restrict its ACL.
2. Load `config.json` (invalid -> built-in strict defaults + degraded), the database lists and the global list (each failure -> that part empty + degraded).
3. Build the immutable rule engine; bind the IPC endpoint (the only fatal failure).
4. Determine upstream DNS servers: `dnsUpstreams` if configured, otherwise discovered from the system without changing anything. None known -> degraded, nothing is redirected.
5. Start the resolver. Not listening on IPv4 loopback -> degraded, nothing is redirected.
6. `reconcile`: adapter DNS, then firewall, then browser policies. Each component reports its own state.
7. Watchdog repeats step 6 every 5 s; discovered upstreams follow DHCP changes.

Stop: the watchdog stops, then (on service Stop / Ctrl+C) firewall removed, adapter DNS restored, policies restored, resolver stopped. On system Shutdown the settings are left in place.

## Query path
```text
program -> Windows DNS client -> 127.0.0.1:53 (agent)
   name -> rules: allowlist ALLOW | custom BLOCK | global BLOCK | default ALLOW
   BLOCK  -> NXDOMAIN (all query types)
   ALLOW  -> upstream (UDP, TCP if truncated) -> check CNAME targets / owners -> answer
```
Every other DNS path (other servers, DoT, known DoH hosts) is closed by the firewall; browsers' own DoH is switched off by policy.

## Data directory (`%ProgramData%\SavingGrace`)
`config.json`, `savinggrace.sqlite`, `enforcement-state.json` (originals needed for restore), `rules/adult-domains.json`, `logs/agent.<date>.log`.

## Not yet implemented
List editing over IPC, attempt logging and statistics (the resolver only keeps in-memory counters), Admin UI (Slovenian/English), temporary disable and its Bible-text challenge, installer, rule updates, classifiers, block page. IPv6-only adapters are only partially handled (IPv6 DNS is set when the resolver listens on `::1`).
