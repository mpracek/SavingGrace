# Installation
There is no installer yet (Phase 8). Developers: see `docs/DEVELOPMENT.md`.
Manual installation on Windows 10 2004+/11, from an elevated prompt, with the release binary:
```text
mkdir "%ProgramData%\SavingGrace\rules"
copy data\adult-domains\domains.json "%ProgramData%\SavingGrace\rules\adult-domains.json"
savinggrace-agent install
savinggrace-agent status
```
`install` registers the service (automatic start) and starts it; the agent then redirects DNS as described in `ADMIN_GUIDE.md`. `savinggrace-agent uninstall` stops the service, restores DNS, firewall and policies and removes the service; data in `%ProgramData%\SavingGrace` is kept. **This path has not been executed on Windows yet.**
