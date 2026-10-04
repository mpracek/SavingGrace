# Admin guide
Configuration file: `%ProgramData%\SavingGrace\config.json`. All keys are optional; unknown keys or invalid values make the agent ignore the whole file, use the defaults and report `degraded`.

| Key | Default | Range |
|---|---|---|
| `temporaryDisableEnabled` | true | boolean |
| `disableChallengeWordCount` | 50 | 10..100 |
| `disableDurationsMinutes` | [5, 15, 30, 60] | integers 1..240 |
| `disableChallengeMaxFailedAttempts` | 3 | 1..20 |
| `attemptRetentionDays` | 90 | 1..3650 |
| `onInvalidInput` | "allow" | "allow" / "block" |
| `uiLanguage` | "sl" | "sl" / "en" |

Check the agent: `savinggrace-agent status`. `agentState` is `running`, `degraded` (see `degradedReasons`) or `stopping`.
