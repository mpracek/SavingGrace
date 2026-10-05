# Phase 03 Report: Network Protection

**Phase**: 3 of 11
**Date**: 2026-10-04

## Summary
Browser-independent filtering is implemented as a **local DNS resolver plus system enforcement** (ADR 007). The DNS filtering is tested with real sockets on Linux. The Windows enforcement (adapter DNS, firewall filters, browser policies) is written and type-checked but **has never been executed on Windows, and Firefox, Brave, Chrome and Edge have not been tested at all in this phase.** The requirement "verify against Firefox, Chrome, Edge, Brave" is therefore **not met yet**; what exists is a CI smoke test (Chrome, Edge) and a manual checklist (all four).

## Research (ADR 002 checked against documentation)
Confirmed: user-mode WFP filters match address/port/protocol/application only; DNS redirection needs a kernel callout; `SetInterfaceDnsSettings` needs Windows 10 build 19041+; the four browsers' DoH-off registry policies and paths (Brave's path to be re-checked on a Brave machine). Consequence: hostnames are decided in DNS; ADR 002 superseded by ADR 007.

## Implemented
- DNS resolver: UDP+TCP, loopback only, NXDOMAIN for blocked names (all qtypes, subdomains), label-based matching without URL parsing, CNAME and answer-owner checks, spoofed/mismatched answer rejection, SERVFAIL on upstream failure, Firefox DoH canary, concurrency limits, in-memory counters only.
- Upstream forwarder: UDP, TCP fallback on truncation, failover, transaction-id check, live-updatable server list.
- Enforcement logic (platform independent, fully unit-tested): adapter DNS redirection with originals persisted first, orphan handling, tamper repair, DHCP-lease-following upstream discovery; declarative firewall rule list (bundled DoH resolver addresses in `data/network/doh-endpoints.json`); browser policy table with prior-value restore; orchestrator with ordering rules.
- Windows backends: IP Helper (`GetAdaptersAddresses`, `Get/SetInterfaceDnsSettings`, DHCP lease from registry), WFP dynamic-session filters (transactional), registry policies.
- Agent: starts resolver, enforces only after the resolver listens and an upstream is known, 5 s watchdog, restore on service Stop/Ctrl+C, settings kept on system Shutdown, honest `networkFiltering` (`not_active`/`dns_only`/`partial`/`enforced`).
- Config keys `dnsEnabled`, `dnsListen` (loopback only), `dnsUpstreams`, `enforceSystemProtection` in Rust and TypeScript.
- Windows smoke test extended (see TESTING.md), with guaranteed cleanup.

## Files
Changed vs Phase 2: see `docs/PHASE-03-CHANGED-FILES.txt`. New: `apps/agent/src/dns/*`, `apps/agent/src/enforce/**`, `apps/agent/tests/{dns,agent_enforcement}.rs`, `data/network/doh-endpoints.json`, `docs/adr/007-dns-enforcement.md`, this report.

## Tests (executed on Linux)
| Suite | Passed |
|---|---|
| TypeScript (vitest) | 188 |
| Rust lib unit tests | 46 |
| Rust `dns` | 17 |
| Rust `agent_enforcement` | 10 |
| Rust `agent_ipc` | 9 |
| Rust `conformance` | 4 |
| **Total** | **274, all passing** |

Also: `npm run check`, `cargo fmt --check`, `cargo clippy -D warnings` (Linux and `x86_64-pc-windows-gnu`), `cargo build --release`, and a manual run of the release binary answering real UDP queries (blocked name, subdomain, uppercase and canary -> NXDOMAIN; look-alike forwarded). Two deliberate code mutations were confirmed to be caught by the tests (one test was too weak at first and was strengthened).

## NOT verified (important)
1. **Nothing Windows-specific has been run**: IP Helper, WFP, registry, service, ACL, named pipe. The smoke test in CI is the first execution; expect fixes. `pwsh` was not available here, so the PowerShell script has not even been syntax-checked.
2. **No browser has been tested.** Firefox and Brave are not automated at all.
3. Behaviour of `SetInterfaceDnsSettings` with an empty string (back to automatic), the WFP weight semantics, whether the SCM repeats the last recovery action, IPv6 handling, WSL2/VM behaviour, VPN interplay: all assumptions from documentation.
4. GitHub Actions has never run.

## Known limitations / security considerations
Residual bypasses are listed in `docs/threat-model/THREAT_MODEL.md`: DoH/DoT to unlisted hosts from non-browser software, direct IP access, VPN/proxy/Tor, hosts-file edits, local administrator. Stopping the service restores everything (by design, ADR 007). A permanently failing service leaves DNS broken until an administrator intervenes. Browsers show "managed by your organization". Requires Windows 10 2004+. Service still runs as LocalSystem. IPC authorization for state-changing commands is still undecided (ADR 006) and blocks Phase 4/7. No block page: blocked sites show the browser's "site can't be reached" error. LICENSE and seed lists are still placeholders.

## Documentation updated
ADR 002 (superseded), ADR 007 (new), ARCHITECTURE, SECURITY, THREAT_MODEL, TESTING (manual checklist), ADMIN_GUIDE, USER_GUIDE, INSTALLATION, TROUBLESHOOTING, DEVELOPMENT, CHANGELOG, README.

## Next phase
Phase 4: Rules (global list, custom list and allowlist persistence over IPC, validation). Blocked on the open IPC authorization decision (ADR 006). Awaiting approval.
