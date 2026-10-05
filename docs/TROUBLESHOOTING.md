# Troubleshooting
- `agentState: degraded`: read `degradedReasons` in `savinggrace-agent status` and the log in `%ProgramData%\SavingGrace\logs`.
- `networkFiltering` is not `enforced`: check `enforcement` for the failing component and its detail. Firewall failures usually mean the Base Filtering Engine service is stopped.
- Resolver cannot listen on port 53: another program holds it (Internet Connection Sharing, a mobile hotspot, some virtualization features). The agent then leaves system DNS unchanged. Stop that program or change `dnsListen` (note that Windows only queries port 53).
- No internet after the service stopped unexpectedly and does not restart: adapter DNS still points at 127.0.0.1. Fix: `savinggrace-agent uninstall`, or set each adapter back to automatic DNS in Windows settings (`Set-DnsClientServerAddress -InterfaceIndex <n> -ResetServerAddresses`).
- Allowed sites do not load but blocked ones behave: upstream DNS problem. Check `dns.upstreams` and `dns.stats.upstreamErrors`; set `dnsUpstreams` explicitly if discovery picked a server that is unreachable.
- Typecheck fails on `@savinggrace/*` imports: run `npm install`. `node:sqlite` not found: Node >= 22.13.
