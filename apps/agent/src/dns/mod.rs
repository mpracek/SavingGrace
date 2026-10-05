//! Local filtering DNS resolver.
//!
//! Every name lookup of every browser (and every other program) on the machine
//! is answered here once system DNS is redirected to the resolver (see `enforce`).
//! Blocked names get NXDOMAIN; everything else is forwarded to the upstream
//! resolvers the system used before. Nothing about queried names is logged or stored.

pub mod filter;
pub mod server;
pub mod upstream;

use serde::Serialize;
use std::sync::atomic::{AtomicU64, Ordering};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transport {
    Udp,
    Tcp,
}

/// In-memory counters only (no names, no addresses). Reset on restart.
#[derive(Debug, Default)]
pub struct DnsStats {
    pub queries: AtomicU64,
    pub blocked: AtomicU64,
    pub forwarded: AtomicU64,
    pub upstream_errors: AtomicU64,
    pub malformed: AtomicU64,
    pub dropped_overload: AtomicU64,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct DnsStatsSnapshot {
    pub queries: u64,
    pub blocked: u64,
    pub forwarded: u64,
    pub upstream_errors: u64,
    pub malformed: u64,
    pub dropped_overload: u64,
}

impl DnsStats {
    pub fn snapshot(&self) -> DnsStatsSnapshot {
        let g = |a: &AtomicU64| a.load(Ordering::Relaxed);
        DnsStatsSnapshot {
            queries: g(&self.queries),
            blocked: g(&self.blocked),
            forwarded: g(&self.forwarded),
            upstream_errors: g(&self.upstream_errors),
            malformed: g(&self.malformed),
            dropped_overload: g(&self.dropped_overload),
        }
    }

    pub(crate) fn bump(counter: &AtomicU64) {
        counter.fetch_add(1, Ordering::Relaxed);
    }
}
