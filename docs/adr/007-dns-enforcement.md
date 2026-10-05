# ADR 007: Browser-independent filtering through a local resolver plus enforcement
**Status**: Accepted (Phase 3). Supersedes ADR 002. Implementation verified by tests on Linux and by type-checking for Windows; **not yet executed on Windows** (see PHASE-03-REPORT.md).

## Context
ADR 002 proposed a layered design but was written from general knowledge. In Phase 3 it was checked against Microsoft and vendor documentation. Findings that change the design:
1. **User-mode WFP cannot decide by hostname.** The documented user-mode `Fwpm*` API adds filters that match on address, port, protocol and application at the ALE layers (for example `FWPM_LAYER_ALE_AUTH_CONNECT_V4/V6` with `FWPM_CONDITION_IP_REMOTE_PORT` or `FWPM_CONDITION_ALE_APP_ID`). Hostname- or SNI-aware decisions need kernel callout drivers.
2. **No transparent redirection from user mode.** Redirecting DNS packets to a local resolver needs a callout. We cannot do it.
3. `SetInterfaceDnsSettings` (IP Helper) can set per-adapter name servers, with separate IPv4 (default) and IPv6 (`DNS_SETTING_IPV6`) settings. It needs **Windows 10 build 19041 (2004) or later**.
4. Chrome, Edge, Brave and Firefox all honour machine-wide registry policies that turn off their private DNS-over-HTTPS: `DnsOverHttpsMode = "off"` under `HKLM\SOFTWARE\Policies\Google\Chrome`, `...\Microsoft\Edge`, `...\BraveSoftware\Brave`, and `DNSOverHTTPS\Enabled = 0` with `Locked = 1` under `...\Mozilla\Firefox`. Browsers then show "managed by your organization". Brave's key path should be re-checked on a machine with Brave installed.

## Decision
Hostname decisions are made **in DNS**, by a resolver the agent runs on loopback, and the operating system is configured so that nothing else can resolve names:
1. **Resolver** (`dns/`): UDP and TCP on `127.0.0.1:53` and `[::1]:53`. Blocked names get NXDOMAIN for every query type; others are forwarded to the DNS servers the system used before. CNAME chains and answer owners are checked (CNAME cloaking). Names are matched without URL parsing. Firefox's DoH canary domain gets NXDOMAIN.
2. **Adapter DNS** (`enforce/dns_redirect`): every operational adapter is pointed at the resolver; originals are persisted before any change, and restored on clean stop.
3. **Firewall** (`enforce/firewall`, `windows/wfp`): outbound port 53 is permitted only to loopback and from the agent process; other DNS and DNS-over-TLS (853) is blocked; HTTPS (TCP/UDP 443) to the addresses of well-known public DoH resolvers is blocked.
4. **Browser policies** (`enforce/browser_policy`): DoH off in the four browsers; prior values recorded and restored.
5. **Watchdog**: every 5 seconds the agent re-checks and repairs all three, counts tampering, and follows DHCP lease changes.

### Safety rules (tested with fakes)
- Enforcement starts only after the resolver listens **and** an upstream DNS server is known; otherwise nothing is changed and the agent reports `degraded`.
- DNS is redirected **before** the firewall closes other paths; the firewall is removed **before** DNS is restored. If DNS redirection fails the firewall is not applied.
- The original DNS setting is written to disk before it is changed. Loopback DNS found without a record (crash leftovers) is remembered as an orphan and reset to automatic on restore.
- The status shows `enforced` only if resolver, DNS, firewall and policies are all applied; otherwise `partial`, `dns_only` or `not_active`.

### Failure semantics (explicit, as required)
- WFP objects live in a **dynamic session**: if the agent dies they vanish (the firewall fails open) but adapter DNS still points at the now-dead resolver, so **name resolution fails closed** until the service restarts (recovery actions: 5 s, 5 s, 30 s; the last action is believed to repeat, unverified). A machine whose service cannot start has no working DNS until an administrator stops/uninstalls the service or resets adapter DNS.
- **Service Stop / uninstall restore everything.** System shutdown does not, so the machine never boots into unfiltered DNS.
- An administrator can therefore stop the service and remove protection. This is inherent to a user-mode design (see threat model).

## Alternatives considered
- **Kernel callout driver / WinDivert-style SNI or DNS interception**: would also catch direct DoH and hostnames in TLS, but needs driver signing, is a large attack surface and a stability risk. Deferred; revisit if the residual risks below prove unacceptable.
- **Local proxy**: only covers proxy-aware applications.
- **hosts file**: cannot hold wildcard rules.
- **`netsh`/PowerShell for DNS settings**: slower, locale-sensitive output; the IP Helper API was chosen.
- **Persistent WFP filters**: would survive an agent crash, but could leave a machine without DNS after an uninstall bug; dynamic session chosen.

## Consequences
Windows 10 2004+ is required. Residual bypasses (documented in the threat model): DoH/DoT to unlisted hosts from non-browser software, direct IP access, VPN and proxy tunnels, a local administrator, hosts-file entries. Port 53 on loopback can be occupied (Internet Connection Sharing, some virtualization features); then the agent stays unenforced and degraded rather than breaking DNS.
