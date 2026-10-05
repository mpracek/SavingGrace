//! Declarative description of the network filters the agent installs.
//!
//! The list is built here as plain data (and unit-tested for safety invariants);
//! `windows/wfp.rs` translates it into Windows Filtering Platform calls.
//!
//! Intent: every program must resolve names through the agent's resolver.
//!  - PERMIT outbound DNS (port 53) to loopback for everybody (clients -> resolver),
//!  - PERMIT outbound DNS from the agent process to anywhere (resolver -> upstream),
//!  - BLOCK all other outbound DNS (port 53) and DNS-over-TLS (port 853),
//!  - BLOCK HTTPS (TCP/UDP 443) to the addresses of well-known public DoH resolvers.
//!
//! Within one sub-layer the highest-weight matching filter decides, so permits
//! carry a higher weight than blocks.

use serde::Deserialize;
use std::net::IpAddr;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IpFamily {
    V4,
    V6,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Proto {
    Tcp,
    Udp,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Permit,
    Block,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AppScope {
    Any,
    /// Only the agent's own executable.
    Agent,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RemoteAddr {
    Any,
    Loopback,
    Exact(IpAddr),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FilterSpec {
    pub name: String,
    pub family: IpFamily,
    pub proto: Proto,
    pub remote_port: u16,
    pub remote: RemoteAddr,
    pub app: AppScope,
    pub verdict: Verdict,
    /// 0..=15 (WFP weight range).
    pub weight: u8,
}

pub const WEIGHT_PERMIT_LOOPBACK: u8 = 15;
pub const WEIGHT_PERMIT_AGENT: u8 = 14;
pub const WEIGHT_BLOCK: u8 = 10;

#[derive(Deserialize)]
struct DohFile {
    version: u32,
    addresses: Vec<String>,
}

/// Public DoH/DoT resolver addresses shipped with the agent (`data/network/doh-endpoints.json`).
pub fn bundled_doh_addresses() -> Vec<IpAddr> {
    const RAW: &str = include_str!("../../../../data/network/doh-endpoints.json");
    parse_doh_addresses(RAW).expect("bundled doh-endpoints.json is validated by tests")
}

pub fn parse_doh_addresses(raw: &str) -> Result<Vec<IpAddr>, String> {
    let f: DohFile = serde_json::from_str(raw).map_err(|e| e.to_string())?;
    if f.version != 1 {
        return Err(format!("unsupported doh list version {}", f.version));
    }
    f.addresses
        .iter()
        .map(|a| {
            a.parse::<IpAddr>()
                .map_err(|_| format!("invalid address \"{a}\""))
        })
        .collect()
}

fn family_of(ip: &IpAddr) -> IpFamily {
    if ip.is_ipv4() {
        IpFamily::V4
    } else {
        IpFamily::V6
    }
}

pub fn build_filter_specs(doh: &[IpAddr]) -> Vec<FilterSpec> {
    let mut specs = Vec::new();
    for family in [IpFamily::V4, IpFamily::V6] {
        for proto in [Proto::Udp, Proto::Tcp] {
            let tag = format!("{family:?}/{proto:?}");
            let mk = |name: &str, port, remote, app, verdict, weight| FilterSpec {
                name: format!("SavingGrace: {name} [{tag}]"),
                family,
                proto,
                remote_port: port,
                remote,
                app,
                verdict,
                weight,
            };
            specs.push(mk(
                "permit DNS to local resolver",
                53,
                RemoteAddr::Loopback,
                AppScope::Any,
                Verdict::Permit,
                WEIGHT_PERMIT_LOOPBACK,
            ));
            specs.push(mk(
                "permit DNS from agent",
                53,
                RemoteAddr::Any,
                AppScope::Agent,
                Verdict::Permit,
                WEIGHT_PERMIT_AGENT,
            ));
            specs.push(mk(
                "block other DNS",
                53,
                RemoteAddr::Any,
                AppScope::Any,
                Verdict::Block,
                WEIGHT_BLOCK,
            ));
            specs.push(mk(
                "block DNS-over-TLS",
                853,
                RemoteAddr::Any,
                AppScope::Any,
                Verdict::Block,
                WEIGHT_BLOCK,
            ));
        }
    }
    for ip in doh {
        for proto in [Proto::Tcp, Proto::Udp] {
            specs.push(FilterSpec {
                name: format!("SavingGrace: block DoH to {ip} [{proto:?}]"),
                family: family_of(ip),
                proto,
                remote_port: 443,
                remote: RemoteAddr::Exact(*ip),
                app: AppScope::Any,
                verdict: Verdict::Block,
                weight: WEIGHT_BLOCK,
            });
        }
    }
    specs
}

/// Windows Filtering Platform (or a test double).
pub trait Firewall {
    /// Installs the filters; replaces any previous set. All-or-nothing.
    fn apply(&mut self, specs: &[FilterSpec]) -> Result<(), String>;
    /// True while every filter installed by `apply` is still present.
    fn verify(&self) -> bool;
    fn remove(&mut self) -> Result<(), String>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn bundled_doh_list_is_valid_and_has_both_families() {
        let ips = bundled_doh_addresses();
        assert!(ips.len() >= 10);
        assert!(ips.iter().any(IpAddr::is_ipv4) && ips.iter().any(IpAddr::is_ipv6));
        assert!(ips
            .iter()
            .all(|i| !i.is_loopback() && !i.is_unspecified() && !i.is_multicast()));
        assert_eq!(
            ips.iter().collect::<HashSet<_>>().len(),
            ips.len(),
            "duplicates"
        );
    }

    #[test]
    fn rejects_bad_doh_files() {
        assert!(parse_doh_addresses("{}").is_err());
        assert!(parse_doh_addresses(r#"{"version":2,"addresses":[]}"#).is_err());
        assert!(parse_doh_addresses(r#"{"version":1,"addresses":["nope"]}"#).is_err());
    }

    #[test]
    fn names_are_unique_and_branded() {
        let specs = build_filter_specs(&bundled_doh_addresses());
        let names: HashSet<_> = specs.iter().map(|s| s.name.clone()).collect();
        assert_eq!(names.len(), specs.len());
        assert!(specs.iter().all(|s| s.name.starts_with("SavingGrace:")));
        assert!(specs.iter().all(|s| s.weight <= 15));
    }

    #[test]
    fn every_dns_block_has_stronger_permits_for_loopback_and_agent() {
        let specs = build_filter_specs(&[]);
        for fam in [IpFamily::V4, IpFamily::V6] {
            for proto in [Proto::Udp, Proto::Tcp] {
                let find = |v, r, a| {
                    specs.iter().find(|s| {
                        s.family == fam
                            && s.proto == proto
                            && s.remote_port == 53
                            && s.verdict == v
                            && s.remote == r
                            && s.app == a
                    })
                };
                let block = find(Verdict::Block, RemoteAddr::Any, AppScope::Any).expect("block 53");
                let lo = find(Verdict::Permit, RemoteAddr::Loopback, AppScope::Any)
                    .expect("loopback permit");
                let agent =
                    find(Verdict::Permit, RemoteAddr::Any, AppScope::Agent).expect("agent permit");
                assert!(
                    lo.weight > block.weight && agent.weight > block.weight,
                    "permits must outrank the block"
                );
            }
        }
    }

    #[test]
    fn blocks_cover_dot_and_both_ip_families_on_both_protocols() {
        let specs = build_filter_specs(&[]);
        for fam in [IpFamily::V4, IpFamily::V6] {
            for proto in [Proto::Udp, Proto::Tcp] {
                assert!(specs.iter().any(|s| s.family == fam
                    && s.proto == proto
                    && s.remote_port == 853
                    && s.verdict == Verdict::Block));
            }
        }
    }

    #[test]
    fn nothing_but_the_agent_or_loopback_is_ever_permitted() {
        for s in build_filter_specs(&bundled_doh_addresses())
            .iter()
            .filter(|s| s.verdict == Verdict::Permit)
        {
            assert!(s.remote_port == 53);
            assert!(
                s.remote == RemoteAddr::Loopback || s.app == AppScope::Agent,
                "{}",
                s.name
            );
        }
    }

    #[test]
    fn doh_blocks_use_the_right_family_and_port() {
        let ips: Vec<IpAddr> = vec![
            "1.1.1.1".parse().unwrap(),
            "2606:4700:4700::1111".parse().unwrap(),
        ];
        let specs = build_filter_specs(&ips);
        let doh: Vec<_> = specs
            .iter()
            .filter(|s| matches!(s.remote, RemoteAddr::Exact(_)))
            .collect();
        assert_eq!(doh.len(), 4);
        for s in doh {
            assert_eq!(s.remote_port, 443);
            let RemoteAddr::Exact(ip) = s.remote else {
                unreachable!()
            };
            assert_eq!(s.family, family_of(&ip));
            assert_eq!(s.verdict, Verdict::Block);
        }
    }
}
