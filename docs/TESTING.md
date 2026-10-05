# Testing
- **TypeScript (vitest, `tests/`)**: domain-matching, rule-engine, configuration (incl. DNS keys), database, integration, conformance (shared vectors + SQL schema equality).
- **Rust (`cargo test`)**:
  - unit tests in `src/` (config, rules, storage, enforcement store, DNS redirect, firewall list, browser policies, `Enforcer` ordering, status computation, GUID parsing),
  - `tests/conformance.rs` (shared vectors),
  - `tests/dns.rs` (DNS filter with a fake upstream, real UDP/TCP sockets, real forwarder against fake DNS servers),
  - `tests/agent_ipc.rs` (boots the real agent, queries it over IPC),
  - `tests/agent_enforcement.rs` (agent with an injected fake enforcement backend: ordering, restore on stop, watchdog, truthful status).
- **Mutation check** (done manually in Phase 3, not automated): breaking the DNS-name evaluation or the CNAME check makes tests fail.
- **Windows (CI)**: `scripts/smoke-windows.ps1` installs the service, checks auto-start, status over the pipe, adapter DNS, resolution of an allowed and a blocked name, direct DNS to 8.8.8.8/1.1.1.1 blocked, DoH endpoint and DoT blocked, browser policies, Chrome and Edge headless (control page loads, blocked page does not), tamper repair, crash recovery, uninstall restores everything. It cleans up even if an assertion fails. **It has never run yet.**

## Manual checklist (not automated): run on a real Windows 10 2004+/11 machine after install
1. `savinggrace-agent status` shows `networkFiltering: "enforced"`.
2. In each of Chrome, Edge, **Firefox** and **Brave**, normal and private window: an allowed site loads; a site from `data/adult-domains/domains.json` and a subdomain of it do not (error page "can't be reached").
3. In each browser open `chrome://policy` / `edge://policy` / `brave://policy` / `about:policies` and confirm the DoH policy is listed.
4. Try to enable Secure DNS / DoH in each browser settings page: the control must be locked or have no effect.
5. `nslookup example.com 8.8.8.8` must time out; `nslookup example.com` must work.
6. Change an adapter's DNS in Settings; within ~10 s it must return to 127.0.0.1.
7. Join another Wi-Fi network or reconnect: browsing keeps working (upstream follows the new DHCP lease).
8. Stop the service: DNS settings return to the original, filters and policies are gone, internet works. Start it again: enforcement returns.
9. Reboot: after login browsing is filtered; kill the service process: it restarts within ~5 s.
10. Record results in the phase report. Known to be unautomated: Firefox and Brave navigation, VPN/proxy/Tor behaviour, WSL2/VMs, IPv6-only networks.
