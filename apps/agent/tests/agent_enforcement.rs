//! Agent-level behaviour of enforcement, with a fake backend injected in place of Windows.
//! Verifies ordering and safety rules: enforce only after the resolver listens and an upstream
//! is known, restore on clean stop, keep settings on system shutdown, watchdog repairs.
#![cfg(unix)]

use hickory_proto::op::{Message, MessageType, Query, ResponseCode};
use hickory_proto::rr::{Name, RecordType};
use savinggrace_agent::agent::{self, AgentOptions, RunningAgent};
use savinggrace_agent::dns::DnsStatsSnapshot;
use savinggrace_agent::enforce::dns_redirect::Listening;
use savinggrace_agent::enforce::{
    ComponentState, EnforcementStatus, PlatformEnforcer, ReconcileOutcome,
};
use savinggrace_agent::ipc::{send_request, IpcEndpoint, Request};
use savinggrace_agent::paths::DataDirs;
use serde_json::Value;
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::net::UdpSocket;

#[derive(Default)]
struct Log {
    discovers: usize,
    reconciles: Vec<Listening>,
    restores: usize,
    tamper: u64,
}

struct FakeEnforcer {
    log: Arc<Mutex<Log>>,
    upstreams: Vec<IpAddr>,
    result: EnforcementStatus,
}

impl PlatformEnforcer for FakeEnforcer {
    fn discover_upstreams(&mut self) -> Vec<IpAddr> {
        self.log.lock().unwrap().discovers += 1;
        self.upstreams.clone()
    }
    fn reconcile(&mut self, l: Listening) -> ReconcileOutcome {
        let mut log = self.log.lock().unwrap();
        log.reconciles.push(l);
        let mut status = self.result.clone();
        status.tamper_events = log.tamper;
        ReconcileOutcome {
            status,
            upstreams: self.upstreams.clone(),
        }
    }
    fn restore(&mut self) -> Vec<String> {
        self.log.lock().unwrap().restores += 1;
        vec![]
    }
}

fn all_applied() -> EnforcementStatus {
    EnforcementStatus::with_all(ComponentState::Applied)
}

const GLOBAL: &str = r#"{"version":2,"updated":"2026-10-04","domains":[{"domain":"bad.example","category":"adult"}]}"#;

fn setup(config: &str) -> (tempfile::TempDir, DataDirs) {
    let tmp = tempfile::tempdir().unwrap();
    let dirs = DataDirs::new(tmp.path());
    dirs.ensure_created().unwrap();
    std::fs::write(&dirs.global_list_file, GLOBAL).unwrap();
    std::fs::write(&dirs.config_file, config).unwrap();
    (tmp, dirs)
}

async fn boot(
    dirs: &DataDirs,
    listen: &str,
    enf: Option<FakeEnforcer>,
    interval_ms: u64,
) -> (RunningAgent, IpcEndpoint) {
    let ep = IpcEndpoint::default_for(dirs);
    let mut o = AgentOptions::new(dirs.clone(), ep.clone());
    o.dns_listen_override = Some(vec![listen.parse().unwrap()]);
    o.enforcer_override = enf.map(|e| Box::new(e) as Box<dyn PlatformEnforcer>);
    o.watchdog_interval = Duration::from_millis(interval_ms);
    (agent::start(o).await.unwrap(), ep)
}

async fn status(ep: &IpcEndpoint) -> Value {
    serde_json::to_value(send_request(ep, &Request::GetStatus).await.unwrap()).unwrap()["result"]
        .clone()
}

fn fake(log: &Arc<Mutex<Log>>, ups: &[&str], result: EnforcementStatus) -> FakeEnforcer {
    FakeEnforcer {
        log: Arc::clone(log),
        upstreams: ups.iter().map(|u| u.parse().unwrap()).collect(),
        result,
    }
}

async fn resolve(addr: SocketAddr, name: &str) -> ResponseCode {
    let s = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let mut m = Message::new();
    m.set_id(1)
        .set_message_type(MessageType::Query)
        .set_recursion_desired(true);
    m.add_query(Query::query(Name::from_str(name).unwrap(), RecordType::A));
    s.send_to(&m.to_vec().unwrap(), addr).await.unwrap();
    let mut buf = vec![0u8; 4096];
    let (n, _) = tokio::time::timeout(Duration::from_secs(5), s.recv_from(&mut buf))
        .await
        .expect("no reply")
        .unwrap();
    Message::from_vec(&buf[..n]).unwrap().response_code()
}

#[tokio::test]
async fn enforces_after_the_resolver_listens_and_reports_enforced() {
    let (_t, dirs) = setup("{}");
    let log = Arc::new(Mutex::new(Log::default()));
    let (agent, ep) = boot(
        &dirs,
        "127.0.0.1:0",
        Some(fake(&log, &["192.0.2.53"], all_applied())),
        3_600_000,
    )
    .await;

    let s = status(&ep).await;
    assert_eq!(s["networkFiltering"], "enforced");
    assert_eq!(s["agentState"], "running");
    assert_eq!(s["enforcement"]["firewall"]["state"], "applied");
    assert_eq!(s["dns"]["upstreams"][0], "192.0.2.53");
    assert_eq!(s["dns"]["listening"].as_array().unwrap().len(), 1);
    {
        let l = log.lock().unwrap();
        assert_eq!(
            l.discovers, 1,
            "upstreams are discovered before the resolver starts"
        );
        assert_eq!(l.reconciles.len(), 1);
        assert!(l.reconciles[0].v4 && !l.reconciles[0].v6);
    }
    // The resolver the system was redirected to really filters.
    let addr = agent.dns_addresses()[0];
    assert_eq!(
        resolve(addr, "shop.bad.example.").await,
        ResponseCode::NXDomain
    );
    let blocked = status(&ep).await["dns"]["stats"]["blocked"]
        .as_u64()
        .unwrap();
    assert_eq!(blocked, 1);
    agent.shutdown(true).await;
}

#[tokio::test]
async fn never_enforces_when_the_resolver_cannot_listen() {
    let (_t, dirs) = setup(r#"{"dnsUpstreams":["192.0.2.1"]}"#);
    let blocker = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let busy = blocker.local_addr().unwrap().to_string();
    let log = Arc::new(Mutex::new(Log::default()));
    let (agent, ep) = boot(
        &dirs,
        &busy,
        Some(fake(&log, &["192.0.2.53"], all_applied())),
        50,
    )
    .await;

    let s = status(&ep).await;
    assert_eq!(s["networkFiltering"], "not_active");
    assert_eq!(s["agentState"], "degraded");
    assert_eq!(s["enforcement"]["systemDns"]["state"], "failed");
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(
        log.lock().unwrap().reconciles.is_empty(),
        "system DNS must not be redirected to a dead resolver"
    );
    agent.shutdown(true).await;
    assert_eq!(log.lock().unwrap().restores, 0);
}

#[tokio::test]
async fn never_enforces_without_a_known_upstream() {
    let (_t, dirs) = setup("{}");
    let log = Arc::new(Mutex::new(Log::default()));
    let (agent, ep) = boot(
        &dirs,
        "127.0.0.1:0",
        Some(fake(&log, &[], all_applied())),
        50,
    )
    .await;
    let s = status(&ep).await;
    assert_eq!(s["agentState"], "degraded");
    assert!(s["degradedReasons"].to_string().contains("upstream"));
    assert_ne!(s["networkFiltering"], "enforced");
    assert!(log.lock().unwrap().reconciles.is_empty());
    agent.shutdown(true).await;
}

#[tokio::test]
async fn configured_upstreams_take_precedence_over_discovery() {
    let (_t, dirs) = setup(r#"{"dnsUpstreams":["192.0.2.7"]}"#);
    let log = Arc::new(Mutex::new(Log::default()));
    let (agent, ep) = boot(
        &dirs,
        "127.0.0.1:0",
        Some(fake(&log, &["192.0.2.53"], all_applied())),
        3_600_000,
    )
    .await;
    assert_eq!(log.lock().unwrap().discovers, 0);
    let s = status(&ep).await;
    assert_eq!(s["networkFiltering"], "enforced");
    // The explicit configuration is not overwritten by what the enforcer sees.
    assert_eq!(s["dns"]["upstreams"], serde_json::json!(["192.0.2.7"]));
    agent.shutdown(true).await;
}

#[tokio::test]
async fn clean_stop_restores_but_system_shutdown_keeps_settings() {
    for (restore, expected) in [(true, 1), (false, 0)] {
        let (_t, dirs) = setup("{}");
        let log = Arc::new(Mutex::new(Log::default()));
        let (agent, _ep) = boot(
            &dirs,
            "127.0.0.1:0",
            Some(fake(&log, &["192.0.2.53"], all_applied())),
            3_600_000,
        )
        .await;
        agent.shutdown(restore).await;
        assert_eq!(
            log.lock().unwrap().restores,
            expected,
            "restore_system={restore}"
        );
    }
}

#[tokio::test]
async fn discovered_upstreams_follow_network_changes() {
    let (_t, dirs) = setup("{}");
    let log = Arc::new(Mutex::new(Log::default()));
    let (agent, ep) = boot(
        &dirs,
        "127.0.0.1:0",
        Some(fake(&log, &["192.0.2.53"], all_applied())),
        30,
    )
    .await;
    assert_eq!(
        status(&ep).await["dns"]["upstreams"],
        serde_json::json!(["192.0.2.53"])
    );
    agent.shutdown(true).await;
}

#[tokio::test]
async fn watchdog_reconciles_repeatedly_and_surfaces_tampering() {
    let (_t, dirs) = setup("{}");
    let log = Arc::new(Mutex::new(Log::default()));
    let (agent, ep) = boot(
        &dirs,
        "127.0.0.1:0",
        Some(fake(&log, &["192.0.2.53"], all_applied())),
        30,
    )
    .await;
    log.lock().unwrap().tamper = 3;
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(
        log.lock().unwrap().reconciles.len() >= 3,
        "watchdog should have run several times"
    );
    assert_eq!(status(&ep).await["enforcement"]["tamperEvents"], 3);
    agent.shutdown(true).await;
    let n = log.lock().unwrap().reconciles.len();
    tokio::time::sleep(Duration::from_millis(150)).await;
    assert_eq!(
        log.lock().unwrap().reconciles.len(),
        n,
        "watchdog stops with the agent"
    );
}

#[tokio::test]
async fn partial_enforcement_is_reported_as_partial_not_enforced() {
    let (_t, dirs) = setup("{}");
    let log = Arc::new(Mutex::new(Log::default()));
    let mut res = all_applied();
    res.firewall = ComponentState::Failed("bfe not running".into());
    let (agent, ep) = boot(
        &dirs,
        "127.0.0.1:0",
        Some(fake(&log, &["192.0.2.53"], res)),
        3_600_000,
    )
    .await;
    let s = status(&ep).await;
    assert_eq!(s["networkFiltering"], "partial");
    assert_eq!(s["enforcement"]["firewall"]["detail"], "bfe not running");
    agent.shutdown(true).await;
}

#[tokio::test]
async fn disabled_resolver_or_disabled_enforcement_is_reported_truthfully() {
    let (_t, dirs) = setup(r#"{"dnsEnabled":false}"#);
    let (agent, ep) = boot(&dirs, "127.0.0.1:0", None, 50).await;
    let s = status(&ep).await;
    assert_eq!(s["networkFiltering"], "not_active");
    assert_eq!(s["dns"]["enabled"], false);
    assert!(agent.dns_addresses().is_empty());
    agent.shutdown(true).await;

    let (_t2, dirs2) = setup(r#"{"enforceSystemProtection":false,"dnsUpstreams":["192.0.2.1"]}"#);
    let (agent2, ep2) = boot(&dirs2, "127.0.0.1:0", None, 50).await;
    let s2 = status(&ep2).await;
    assert_eq!(s2["networkFiltering"], "dns_only");
    assert_eq!(s2["enforcement"]["systemDns"]["state"], "disabled");
    agent2.shutdown(true).await;
}

#[test]
fn stats_snapshot_serialises_with_camel_case_keys() {
    let v = serde_json::to_value(DnsStatsSnapshot {
        queries: 1,
        blocked: 2,
        forwarded: 3,
        upstream_errors: 4,
        malformed: 5,
        dropped_overload: 6,
    })
    .unwrap();
    assert_eq!(v["upstreamErrors"], 4);
    assert_eq!(v["droppedOverload"], 6);
}
