# Admin guide
Configuration file: `%ProgramData%\SavingGrace\config.json`. All keys are optional; unknown keys or invalid values make the agent ignore the whole file, use the defaults and report `degraded`.

| Key | Default | Range / meaning |
|---|---|---|
| `temporaryDisableEnabled` | true | boolean |
| `disableChallengeWordCount` | 50 | 10..100 |
| `disableDurationsMinutes` | [5, 15, 30, 60] | integers 1..240 |
| `disableChallengeMaxFailedAttempts` | 3 | 1..20 |
| `attemptRetentionDays` | 90 | 1..3650 |
| `onInvalidInput` | "allow" | "allow" / "block" |
| `uiLanguage` | "sl" | "sl" / "en" |
| `dnsEnabled` | true | run the local resolver; `false` means nothing is filtered |
| `dnsListen` | ["127.0.0.1:53", "[::1]:53"] | loopback `ip:port` only; other addresses are rejected |
| `dnsUpstreams` | [] | IPs (optionally `:port`, default 53), not loopback. Empty = use the DNS servers the system used before. When set, they are used as-is and not updated on network changes |
| `enforceSystemProtection` | true | redirect adapter DNS, install firewall filters and browser policies. `false` is for development: the resolver runs but nothing forces programs to use it |

## Checking the agent
`savinggrace-agent status` prints JSON:
- `agentState`: `running`, `degraded` (see `degradedReasons`), `stopping`.
- `networkFiltering`: `enforced` (all of resolver, DNS redirection, firewall, browser policies in place), `partial`, `dns_only`, `not_active`. Only `enforced` means the design's protection is complete.
- `dns`: listening addresses, failed binds, upstream servers, counters (`queries`, `blocked`, `forwarded`, `upstreamErrors`, `malformed`, `droppedOverload`). Counters are in memory and reset on restart; no names are kept.
- `enforcement`: state of `systemDns`, `firewall`, `browserPolicies` (`applied`, `failed` + detail, `disabled`, `unsupported`) and `tamperEvents`.

## What changes on the machine (and is undone on service Stop/uninstall)
- Adapter DNS servers set to 127.0.0.1 (and ::1). The originals are saved in `enforcement-state.json` in the data directory. **Do not delete that file while the service is running.**
- Windows Filtering Platform filters (sub-layer "SavingGrace DNS enforcement"), dynamic: they disappear if the agent process ends.
- Browser policy values under `HKLM\SOFTWARE\Policies\...` for Chrome, Edge, Brave and Firefox. Browsers will say "Managed by your organization".
- Requirements: Windows 10 build 19041 (2004) or later; the Base Filtering Engine service must be running.
