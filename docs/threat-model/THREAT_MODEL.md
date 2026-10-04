# Threat model (initial)

**Assets**: the user's intent to avoid adult content; local configuration and rule lists; blocked-attempt log (privacy-sensitive).
**Adversary**: the machine's own user in a weak moment (impulsive bypass), not a skilled attacker with malware-level capabilities.

## Bypass vectors to address (status: all open, Phase 3/9)
| Vector | Status |
|---|---|
| Other browser / private mode | Open: needs system-level filtering |
| DNS-over-HTTPS / alternative DNS | Open |
| VPN / proxy | Open; likely only partially preventable in user mode |
| Direct IP access | Open; IP rules exist but cannot enumerate sites |
| Encrypted ClientHello / QUIC (hides SNI) | Open |
| Stopping/uninstalling the service as local admin | Open; cannot be fully prevented for an administrator |
| Editing the DB/config as a standard user | Mitigated in code (protected DACL on %ProgramData%\\SavingGrace), unverified on Windows |
| Squatting the IPC pipe name before the service starts | Mitigated in code (first pipe instance), unverified on Windows |
| Standard user changing state over IPC | Not applicable yet (IPC is read-only); open for Phase 4/7 (ADR 006) |
| Process killed | Mitigated: SCM restarts the service (smoke test in CI, unverified) |
| Hostname tricks (case, dot, port, punycode, lookalikes) | Mitigated in the matcher, covered by tests |

Anything that cannot be prevented in user mode will be documented here rather than claimed as solved.
