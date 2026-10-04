# ADR 002: Network filtering approach
**Status**: Proposed, NOT verified in Phase 1
**Context**: DNS filtering alone is bypassable (DoH, alternative resolvers). Hostname-level decisions need DNS or TLS SNI visibility.
**Decision (candidate, to be validated against current Microsoft documentation in Phase 3)**: layered: local resolver/sinkhole driven by the rule engine; Windows Filtering Platform rules to force DNS through it and block known DoH/DoT endpoints; browser policy settings to disable DoH; optional SNI inspection.
**Alternatives**: transparent proxy; kernel callout driver (needs driver signing, high risk).
**Consequences**: ECH/QUIC, VPNs and proxies may remain partly unblockable in user mode; to be documented in the threat model.
