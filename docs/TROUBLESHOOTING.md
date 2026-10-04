# Troubleshooting
- `agentState: degraded`: read `degradedReasons` in `savinggrace-agent status` and the log in `%ProgramData%\SavingGrace\logs`.
- "cannot bind IPC endpoint": another instance already runs (stop the service first).
- Typecheck fails on `@savinggrace/*` imports: run `npm install`.
- `node:sqlite` not found: upgrade Node to >= 22.13.
