# Security (Phase 3 scope)

## What is tested (automatically, on Linux)
- Hostname matching and rule priority; the same vectors pass in TypeScript and Rust.
- DNS filter: NXDOMAIN for every query type on blocked names and subdomains, look-alike names untouched, allowlist precedence, CNAME cloaking, answer-owner check, Firefox canary, malformed/oversized/multi-question/non-query packets, spoofed answers (wrong id or question) -> SERVFAIL, upstream failure -> SERVFAIL, real UDP and TCP sockets, 100 concurrent queries, failover and TCP fallback. Two deliberate code mutations (URL parsing in the DNS path, CNAME check removed) are caught by the tests.
- Enforcement logic with fakes: ordering (DNS before firewall, firewall removed before DNS restored), firewall never applied if DNS redirection failed, originals persisted before change, tamper detection and repair, restart without overwriting originals, orphaned loopback DNS, DHCP lease changes, restore retries, policy restore to prior values.
- Firewall rule list invariants: every DNS block has stronger permits only for loopback and the agent; IPv4 and IPv6, UDP and TCP covered.
- Agent: enforce only after the resolver listens and an upstream is known; restore on clean stop, keep on shutdown; watchdog; truthful status.

## What is NOT verified
**None of the Windows code has been run.** The IP Helper, WFP and registry backends, the service, ACL hardening and named pipe are type-checked and linted via cross-compilation only. The Windows smoke test (`scripts/smoke-windows.ps1`, in CI) is the first real execution and also drives Chrome and Edge headless. Firefox and Brave were not exercised at all. Do not rely on the protection until that script has passed on a real Windows machine.

## Security properties designed in
- The resolver listens only on loopback (configuration rejects other addresses): it can never become an open resolver.
- Names are matched on DNS labels without a URL parser, so unusual label bytes cannot hide a blocked suffix.
- No query names or addresses are logged or stored; only in-memory counters.
- Data directory ACL: SYSTEM and Administrators only. Original DNS settings are stored there.
- IPC is read-only (ADR 006). `check_domain` evaluates a name and logs nothing.
- Fail-safe rules and failure semantics: see ADR 007.

## Known limitations
See the threat model. In short: a local administrator can stop the service (which restores everything); DoH/DoT to unlisted hosts from non-browser software, direct IP access, VPNs, proxies, hosts-file entries and anything outside the Windows resolver path are not covered.
