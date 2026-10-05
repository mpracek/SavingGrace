# ADR 002: Network filtering approach
**Status**: Superseded by ADR 007 (Phase 3)

The Phase 1 proposal (local resolver, WFP rules forcing DNS, blocked DoH endpoints, browser policies, optional SNI inspection) was verified against current documentation in Phase 3. The core idea held; two parts changed: hostname decisions must happen in DNS because user-mode WFP cannot match hostnames or redirect traffic, and SNI inspection is not available without a kernel driver. See ADR 007 for the decision, sources and consequences.
