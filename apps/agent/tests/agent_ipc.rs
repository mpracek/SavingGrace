//! End-to-end: boot the real agent in a temp data dir and talk to it over IPC.
//! Unix-socket transport only; the Windows named-pipe transport is exercised by
//! scripts/smoke-windows.ps1 in CI (not run in the development sandbox).
#![cfg(unix)]

use savinggrace_agent::agent::{self, AgentOptions, RunningAgent};
use savinggrace_agent::ipc::{send_request, IpcEndpoint, Request, MAX_FRAME_BYTES};
use savinggrace_agent::paths::DataDirs;
use savinggrace_agent::storage::{Database, ListKind};
use serde_json::Value;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;

const GLOBAL_LIST: &str = r#"{"version":2,"updated":"2026-10-04","domains":[{"domain":"bad.example","category":"adult"}]}"#;

fn dirs_with(global: Option<&str>, config: Option<&str>) -> (tempfile::TempDir, DataDirs) {
    let tmp = tempfile::tempdir().unwrap();
    let dirs = DataDirs::new(tmp.path());
    dirs.ensure_created().unwrap();
    if let Some(g) = global {
        std::fs::write(&dirs.global_list_file, g).unwrap();
    }
    // Without an upstream resolver the agent is (correctly) degraded; tests supply a documentation-range one.
    std::fs::write(
        &dirs.config_file,
        config.unwrap_or(r#"{"dnsUpstreams":["192.0.2.1"]}"#),
    )
    .unwrap();
    (tmp, dirs)
}

async fn boot(dirs: &DataDirs) -> (RunningAgent, IpcEndpoint) {
    let endpoint = IpcEndpoint::default_for(dirs);
    let mut opts = AgentOptions::new(dirs.clone(), endpoint.clone());
    // Never bind the real port 53 in tests.
    opts.dns_listen_override = Some(vec!["127.0.0.1:0".parse().unwrap()]);
    let running = agent::start(opts).await.unwrap();
    (running, endpoint)
}

async fn call(ep: &IpcEndpoint, req: &Request) -> Value {
    let r = send_request(ep, req).await.unwrap();
    serde_json::to_value(r).unwrap()
}

#[tokio::test]
async fn healthy_boot_reports_running_and_never_claims_filtering() {
    let (_t, dirs) = dirs_with(Some(GLOBAL_LIST), None);
    let db = Database::open(&dirs.database_file).unwrap();
    db.add_domain(ListKind::CustomBlocklist, "mine.example", true)
        .unwrap();
    db.add_domain(ListKind::Allowlist, "ok.bad.example", false)
        .unwrap();
    drop(db);

    let (agent, ep) = boot(&dirs).await;
    let s = call(&ep, &Request::GetStatus).await;
    assert_eq!(s["ok"], true);
    let r = &s["result"];
    assert_eq!(r["agentState"], "running");
    // The resolver listens, but nothing forces programs to use it: the agent must say "dns_only".
    assert_eq!(r["networkFiltering"], "dns_only");
    assert_eq!(r["enforcement"]["systemDns"]["state"], "unsupported");
    assert_eq!(r["rules"]["globalList"]["count"], 1);
    assert_eq!(r["rules"]["customBlocklist"], 1);
    assert_eq!(r["rules"]["allowlist"], 1);
    assert_eq!(r["config"]["disableChallengeWordCount"], 50);
    assert_eq!(r["config"]["uiLanguage"], "sl");
    assert_eq!(r["degradedReasons"].as_array().unwrap().len(), 0);

    let p = call(&ep, &Request::Ping).await;
    assert_eq!(p["result"]["protocolVersion"], 1);
    agent.shutdown(true).await;
}

#[tokio::test]
async fn check_domain_applies_rule_priority_from_disk() {
    let (_t, dirs) = dirs_with(Some(GLOBAL_LIST), None);
    let db = Database::open(&dirs.database_file).unwrap();
    db.add_domain(ListKind::Allowlist, "ok.bad.example", false)
        .unwrap();
    drop(db);
    let (agent, ep) = boot(&dirs).await;

    let check = |t: &str| Request::CheckDomain {
        target: t.to_string(),
    };
    let d = call(&ep, &check("WWW.Bad.Example.")).await;
    assert_eq!(d["result"]["action"], "BLOCK");
    assert_eq!(d["result"]["ruleType"], "global_blocklist");
    assert_eq!(d["result"]["matchedRule"], "bad.example");
    assert_eq!(
        call(&ep, &check("ok.bad.example")).await["result"]["ruleType"],
        "allowlist"
    );
    assert_eq!(
        call(&ep, &check("bad.example.evil.com")).await["result"]["action"],
        "ALLOW"
    );
    assert_eq!(
        call(&ep, &check("not a host")).await["result"]["ruleType"],
        "invalid_input"
    );
    agent.shutdown(true).await;
}

#[tokio::test]
async fn missing_global_list_degrades_but_still_serves() {
    let (_t, dirs) = dirs_with(None, None);
    let (agent, ep) = boot(&dirs).await;
    let s = call(&ep, &Request::GetStatus).await;
    assert_eq!(s["result"]["agentState"], "degraded");
    assert!(s["result"]["degradedReasons"][0]
        .as_str()
        .unwrap()
        .contains("global"));
    agent.shutdown(true).await;
}

#[tokio::test]
async fn invalid_config_falls_back_to_strict_defaults() {
    let (_t, dirs) = dirs_with(
        Some(GLOBAL_LIST),
        Some(r#"{"disableChallengeWordCount": 3, "temporaryDisableEnabled": false}"#),
    );
    let (agent, ep) = boot(&dirs).await;
    let s = call(&ep, &Request::GetStatus).await;
    assert_eq!(s["result"]["agentState"], "degraded");
    // Defaults, not the half-valid user file.
    assert_eq!(s["result"]["config"]["temporaryDisableEnabled"], true);
    assert_eq!(s["result"]["config"]["disableChallengeWordCount"], 50);
    agent.shutdown(true).await;
}

#[tokio::test]
async fn valid_config_is_applied() {
    let (_t, dirs) = dirs_with(
        Some(GLOBAL_LIST),
        Some(
            r#"{"disableChallengeWordCount": 25, "uiLanguage": "en", "dnsUpstreams": ["192.0.2.1"]}"#,
        ),
    );
    let (agent, ep) = boot(&dirs).await;
    let s = call(&ep, &Request::GetStatus).await;
    assert_eq!(s["result"]["agentState"], "running");
    assert_eq!(s["result"]["config"]["disableChallengeWordCount"], 25);
    assert_eq!(s["result"]["config"]["uiLanguage"], "en");
    agent.shutdown(true).await;
}

#[tokio::test]
async fn corrupt_database_degrades_instead_of_crashing() {
    let (_t, dirs) = dirs_with(Some(GLOBAL_LIST), None);
    std::fs::write(
        &dirs.database_file,
        b"this is not a sqlite database at all, just text padding.....",
    )
    .unwrap();
    let (agent, ep) = boot(&dirs).await;
    let s = call(&ep, &Request::GetStatus).await;
    assert_eq!(s["result"]["agentState"], "degraded");
    // Global list protection still works without the DB.
    let d = call(
        &ep,
        &Request::CheckDomain {
            target: "bad.example".into(),
        },
    )
    .await;
    assert_eq!(d["result"]["action"], "BLOCK");
    agent.shutdown(true).await;
}

#[tokio::test]
async fn protocol_abuse_is_rejected_without_killing_the_agent() {
    let (_t, dirs) = dirs_with(Some(GLOBAL_LIST), None);
    let (agent, ep) = boot(&dirs).await;

    // Unknown command and malformed JSON -> structured error, connection stays usable.
    let mut s = UnixStream::connect(&ep.0).await.unwrap();
    s.write_all(b"{\"command\":\"format_disk\"}\nnot json\n{\"command\":\"ping\"}\n")
        .await
        .unwrap();
    let mut buf = vec![0u8; 4096];
    let mut got = String::new();
    while got.lines().count() < 3 {
        let n = s.read(&mut buf).await.unwrap();
        assert!(n > 0, "connection closed early: {got}");
        got.push_str(&String::from_utf8_lossy(&buf[..n]));
    }
    let lines: Vec<Value> = got
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    assert_eq!(lines[0]["error"]["code"], "bad_request");
    assert_eq!(lines[1]["error"]["code"], "bad_request");
    assert_eq!(lines[2]["ok"], true);

    // Oversized frame -> error and the connection is closed. (A client that floods far more than
    // the limit may instead see a connection reset, which is equally a rejection.)
    let mut big = UnixStream::connect(&ep.0).await.unwrap();
    big.write_all(&vec![b'a'; MAX_FRAME_BYTES + 100])
        .await
        .unwrap();
    let mut out = String::new();
    let _ = big.read_to_string(&mut out).await;
    assert!(out.contains("too_large"), "got: {out}");

    let mut flood = UnixStream::connect(&ep.0).await.unwrap();
    let _ = flood.write_all(&vec![b'a'; MAX_FRAME_BYTES * 64]).await;
    let mut sink = Vec::new();
    let _ = flood.read_to_end(&mut sink).await;

    // Agent still healthy afterwards.
    assert_eq!(call(&ep, &Request::Ping).await["ok"], true);
    agent.shutdown(true).await;
}

#[tokio::test]
async fn shutdown_removes_endpoint_and_restart_works() {
    let (_t, dirs) = dirs_with(Some(GLOBAL_LIST), None);
    let (agent, ep) = boot(&dirs).await;
    assert!(ep.0.exists());
    agent.shutdown(true).await;
    assert!(!ep.0.exists());
    assert!(send_request(&ep, &Request::Ping).await.is_err());

    // Same data dir, new process lifetime: state is rebuilt from disk.
    let (agent2, ep2) = boot(&dirs).await;
    assert_eq!(
        call(&ep2, &Request::GetStatus).await["result"]["rules"]["globalList"]["count"],
        1
    );
    agent2.shutdown(true).await;
}

#[tokio::test]
async fn stale_socket_from_a_crash_does_not_block_startup() {
    let (_t, dirs) = dirs_with(Some(GLOBAL_LIST), None);
    let ep = IpcEndpoint::default_for(&dirs);
    std::fs::write(&ep.0, b"stale").unwrap();
    let (agent, ep) = boot(&dirs).await;
    assert_eq!(call(&ep, &Request::Ping).await["ok"], true);
    agent.shutdown(true).await;
}
