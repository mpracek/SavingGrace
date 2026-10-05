# Threat model (Phase 3)

**Assets**: the user's intent to avoid adult content; local configuration and rule lists; the log of blocked attempts (privacy-sensitive, not yet written).
**Adversary**: the machine's own user in a weak moment (impulsive bypass), not malware or a determined administrator.

"Status" says what the design achieves. **Every row marked (unverified on Windows) depends on code that has not been executed on Windows yet.**

| Vector | Status |
|---|---|
| Other browser, private/incognito window | Covered: all browsers use the system resolver; their DoH is switched off by policy (unverified on Windows) |
| Browser built-in DoH (Chrome, Edge, Brave, Firefox) | Mitigated by registry policy + blocked DoH resolver addresses + Firefox canary (unverified on Windows) |
| Changing adapter DNS to another server | Repaired within ~5 s, counted as tampering; direct DNS to other servers is blocked meanwhile (unverified on Windows) |
| Alternative DNS typed into an app (`nslookup x 8.8.8.8`) | Blocked by firewall (port 53 and 853) (unverified on Windows) |
| DoH/DoT to a host NOT in the bundled list | **Not prevented** for software other than the four browsers. A DoH server is indistinguishable from any HTTPS site without hostname/SNI inspection (needs a kernel driver) |
| Direct IP access (`http://203.0.113.5/`) | **Not prevented**: no DNS lookup happens. IP rules are not applied by the resolver |
| hosts-file entry for a blocked name | **Not prevented** (needs administrator rights) |
| VPN client with its own resolver or tunnelled DNS | **Not prevented**: DNS inside the tunnel is invisible. Adapter DNS of the VPN adapter is redirected to us, but tunnel software can resolve elsewhere |
| Proxy (HTTP/SOCKS) that resolves names remotely, Tor | **Not prevented** |
| CNAME cloaking | Mitigated: CNAME targets and answer owners are checked |
| Names that exist only in IPv6-only networks | Partially handled; IPv6-only adapters are untested |
| WSL2, virtual machines, containers | Unknown/untested; they may resolve through paths this design does not control |
| ECH, QUIC | Not relevant to a DNS-level design (no SNI inspection); QUIC is not blocked |
| Resolver unavailable (crash) | DNS fails closed until restart (5 s, 5 s, 30 s, last believed to repeat). A permanently failing service leaves the machine without DNS until an administrator intervenes |
| Port 53 occupied (Internet Connection Sharing etc.) | Agent stays degraded and does NOT redirect DNS |
| Local administrator stops or uninstalls the service, edits registry/firewall | **Not preventable in user mode.** Stop/uninstall restore the system. Edits are repaired while the service runs |
| Standard user changing state over IPC | Not applicable yet (IPC is read-only); open for Phase 4/7 (ADR 006) |
| Standard user editing data directory | Mitigated: protected ACL (unverified on Windows) |
| Allowed name that is not in any list | Protection is only as good as the lists; classifiers arrive in Phase 11 |

Residual risk that would justify a kernel-mode component (revisit per ADR 007): direct IP access, unlisted DoH, VPN-less proxying.
