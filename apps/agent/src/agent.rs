//! Agent lifecycle: load configuration, load rules, start the resolver and IPC,
//! enforce, watch, and shut down.
//!
//! Fail-safe policy (tested): a broken component never prevents the agent from
//! starting; it is skipped, logged and reported as `degraded` with a reason.
//! - invalid/unreadable config   -> built-in defaults (strict)
//! - database cannot be opened   -> custom lists unavailable
//! - global list missing/invalid -> no global blocklist
//! - resolver cannot listen      -> system DNS is NOT redirected (never point the machine at a dead resolver)
//! - no upstream DNS server known -> system DNS is NOT redirected
//!
//! The agent only refuses to start if the IPC endpoint cannot be bound.

use crate::config::{load_config_file, parse_upstream, AppConfig};
use crate::dns::filter::DnsFilter;
use crate::dns::server::{self, DnsServerHandle};
use crate::dns::upstream::UdpTcpUpstream;
use crate::enforce::dns_redirect::Listening;
use crate::enforce::{ComponentState, EnforcementStatus, PlatformEnforcer};
use crate::ipc::{self, IpcEndpoint};
use crate::paths::DataDirs;
use crate::rules::{load_global_list_file, RuleEngine};
use crate::state::{DnsRuntime, GlobalListInfo, Shared};
use crate::storage::{Database, ListKind};
use anyhow::Context;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::watch;
use tokio::task::JoinHandle;

pub struct AgentOptions {
    pub dirs: DataDirs,
    pub endpoint: IpcEndpoint,
    /// Overrides `dnsListen` from the configuration (tests use ephemeral ports).
    pub dns_listen_override: Option<Vec<SocketAddr>>,
    /// Replaces the platform enforcement backend (tests inject a fake).
    pub enforcer_override: Option<Box<dyn PlatformEnforcer>>,
    /// How often enforcement is verified and repaired.
    pub watchdog_interval: Duration,
}

impl AgentOptions {
    pub fn new(dirs: DataDirs, endpoint: IpcEndpoint) -> Self {
        Self {
            dirs,
            endpoint,
            dns_listen_override: None,
            enforcer_override: None,
            watchdog_interval: Duration::from_secs(5),
        }
    }
}

type SharedEnforcer = Arc<Mutex<Box<dyn PlatformEnforcer>>>;

pub struct RunningAgent {
    shared: Arc<Shared>,
    ipc_shutdown: watch::Sender<bool>,
    ipc_server: JoinHandle<()>,
    watchdog_shutdown: watch::Sender<bool>,
    watchdog: Option<JoinHandle<()>>,
    dns_shutdown: watch::Sender<bool>,
    dns: Option<DnsServerHandle>,
    enforcer: Option<SharedEnforcer>,
}

impl RunningAgent {
    pub fn shared(&self) -> Arc<Shared> {
        Arc::clone(&self.shared)
    }

    /// Addresses the DNS resolver actually listens on.
    pub fn dns_addresses(&self) -> Vec<SocketAddr> {
        self.dns
            .as_ref()
            .map(|d| d.bound.clone())
            .unwrap_or_default()
    }

    /// Stops the agent. `restore_system` = true (service Stop, uninstall, Ctrl+C) puts DNS settings,
    /// firewall filters and browser policies back so a stopped agent never leaves the machine without
    /// name resolution. On system shutdown it is false: settings stay, so at the next boot names do not
    /// resolve unfiltered before the service is up.
    pub async fn shutdown(self, restore_system: bool) {
        self.shared.set_stopping();
        let _ = self.watchdog_shutdown.send(true);
        if let Some(w) = self.watchdog {
            let _ = w.await;
        }
        if let (true, Some(enf)) = (restore_system, self.enforcer.clone()) {
            // The resolver keeps answering while settings are put back.
            let errors = tokio::task::spawn_blocking(move || {
                enf.lock().unwrap_or_else(|e| e.into_inner()).restore()
            })
            .await
            .unwrap_or_else(|e| vec![format!("restore task failed: {e}")]);
            for e in errors {
                tracing::error!("restore: {e}");
            }
        }
        let _ = self.dns_shutdown.send(true);
        if let Some(d) = self.dns {
            d.join().await;
        }
        let _ = self.ipc_shutdown.send(true);
        let _ = self.ipc_server.await;
        tracing::info!("agent stopped");
    }
}

async fn run_blocking<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> Option<T> {
    tokio::task::spawn_blocking(f).await.ok()
}

pub async fn start(mut opts: AgentOptions) -> anyhow::Result<RunningAgent> {
    let dirs = opts.dirs.clone();
    let mut degraded: Vec<String> = Vec::new();
    tracing::info!("agent {} starting", crate::VERSION);

    dirs.ensure_created()
        .with_context(|| format!("cannot create data directory {}", dirs.root.display()))?;

    #[cfg(windows)]
    if let Err(e) = crate::security_windows::harden_directory(&dirs.root) {
        tracing::error!("cannot restrict data directory permissions: {e:#}");
        degraded.push("data directory permissions could not be restricted".into());
    }

    let config = match load_config_file(&dirs.config_file) {
        Ok(c) => c,
        Err(e) => {
            tracing::error!("{e}; using built-in defaults");
            degraded.push("configuration invalid; defaults in use".into());
            AppConfig::default()
        }
    };

    let (allow, custom) = match Database::open(&dirs.database_file).and_then(|db| {
        Ok((
            db.list_domains(ListKind::Allowlist)?,
            db.list_domains(ListKind::CustomBlocklist)?,
        ))
    }) {
        Ok(lists) => lists,
        Err(e) => {
            tracing::error!("database unavailable: {e}");
            degraded.push("database unavailable; custom lists not loaded".into());
            (vec![], vec![])
        }
    };

    let (global_entries, global_info) = match load_global_list_file(&dirs.global_list_file) {
        Ok(list) => {
            let info = GlobalListInfo {
                count: list.entries.len(),
                version: list.version,
                updated: list.updated,
            };
            (list.entries, Some(info))
        }
        Err(e) => {
            tracing::error!("{e}");
            degraded.push("global adult-domain list not loaded".into());
            (vec![], None)
        }
    };

    let engine = match RuleEngine::new(&allow, &custom, &global_entries, config.on_invalid_input) {
        Ok(e) => e,
        Err(e) => {
            tracing::error!("rule engine could not be built from stored lists: {e}");
            degraded.push("rules could not be loaded".into());
            RuleEngine::new(&[], &[], &[], config.on_invalid_input).map_err(anyhow::Error::msg)?
        }
    };

    let shared = Arc::new(Shared::new(engine, config.clone(), global_info, degraded));
    let (ipc_tx, ipc_rx) = watch::channel(false);
    let ipc_server = ipc::bind(&opts.endpoint, Arc::clone(&shared), ipc_rx)
        .await
        .with_context(|| format!("cannot bind IPC endpoint {}", opts.endpoint))?;

    let (watchdog_tx, watchdog_rx) = watch::channel(false);
    let (dns_tx, dns_rx) = watch::channel(false);
    let mut agent = RunningAgent {
        shared: Arc::clone(&shared),
        ipc_shutdown: ipc_tx,
        ipc_server,
        watchdog_shutdown: watchdog_tx,
        watchdog: None,
        dns_shutdown: dns_tx,
        dns: None,
        enforcer: None,
    };

    start_dns_and_enforcement(&mut agent, &mut opts, &config, &dirs, dns_rx, watchdog_rx).await;

    let st = shared.status();
    tracing::info!(
        "agent ready (state: {:?}, network filtering: {:?})",
        st.agent_state,
        st.network_filtering
    );
    Ok(agent)
}

fn platform_enforcer(
    config: &AppConfig,
    dirs: &DataDirs,
    shared: &Shared,
) -> Option<Box<dyn PlatformEnforcer>> {
    if !config.enforce_system_protection {
        return None;
    }
    #[cfg(windows)]
    {
        match crate::enforce::windows::platform_enforcer(dirs) {
            Ok((e, warning)) => {
                if let Some(w) = warning {
                    tracing::warn!("{w}");
                }
                Some(e)
            }
            Err(e) => {
                tracing::error!("enforcement unavailable: {e}");
                shared.add_degraded("system enforcement could not be initialised");
                None
            }
        }
    }
    #[cfg(not(windows))]
    {
        let _ = (dirs, shared);
        None
    }
}

async fn start_dns_and_enforcement(
    agent: &mut RunningAgent,
    opts: &mut AgentOptions,
    config: &AppConfig,
    dirs: &DataDirs,
    dns_rx: watch::Receiver<bool>,
    watchdog_rx: watch::Receiver<bool>,
) {
    let shared = Arc::clone(&agent.shared);
    if !config.dns_enabled {
        tracing::warn!("DNS resolver disabled by configuration; nothing is filtered");
        shared.set_enforcement(EnforcementStatus::with_all(ComponentState::Disabled));
        return;
    }

    let listen: Vec<SocketAddr> = opts.dns_listen_override.clone().unwrap_or_else(|| {
        config
            .dns_listen
            .iter()
            .filter_map(|a| a.parse().ok())
            .collect()
    });

    let enforcer: Option<SharedEnforcer> = opts
        .enforcer_override
        .take()
        .or_else(|| platform_enforcer(config, dirs, &shared))
        .map(|e| Arc::new(Mutex::new(e)));
    let unavailable = if config.enforce_system_protection {
        ComponentState::Unsupported
    } else {
        ComponentState::Disabled
    };

    // Upstreams: explicit configuration wins; otherwise what the system used before we arrived.
    let configured: Vec<SocketAddr> = config
        .dns_upstreams
        .iter()
        .filter_map(|u| parse_upstream(u))
        .collect();
    let configured_empty = configured.is_empty();
    let upstream_addrs = if !configured.is_empty() {
        configured
    } else if let Some(enf) = enforcer.clone() {
        run_blocking(move || {
            enf.lock()
                .unwrap_or_else(|e| e.into_inner())
                .discover_upstreams()
        })
        .await
        .unwrap_or_default()
        .into_iter()
        .map(|ip| SocketAddr::new(ip, 53))
        .collect()
    } else {
        Vec::new()
    };
    if upstream_addrs.is_empty() {
        tracing::error!("no upstream DNS servers known; names that are allowed cannot be resolved");
        shared.add_degraded("no upstream DNS servers known");
    }

    let upstream = UdpTcpUpstream::new(upstream_addrs.clone(), Duration::from_secs(3));
    let filter = Arc::new(DnsFilter::new(
        Arc::clone(&shared),
        upstream,
        shared.dns_stats(),
    ));
    let handle = server::start(&listen, Arc::clone(&filter), dns_rx).await;
    for (addr, why) in &handle.failed {
        tracing::error!("resolver cannot listen on {addr}: {why}");
    }
    let runtime = |handle: &DnsServerHandle, ups: &[SocketAddr]| DnsRuntime {
        enabled: true,
        listening: handle.bound.iter().map(ToString::to_string).collect(),
        failed: handle
            .failed
            .iter()
            .map(|(a, w)| format!("{a}: {w}"))
            .collect(),
        upstreams: ups.iter().map(|u| u.ip().to_string()).collect(),
    };
    shared.set_dns_runtime(runtime(&handle, &upstream_addrs));

    let v4 = handle.is_bound(true);
    let v6 = handle.is_bound(false);
    agent.dns = Some(handle);

    if !v4 {
        shared.add_degraded("DNS resolver could not listen on IPv4 loopback");
        let why =
            ComponentState::Failed("resolver is not listening; system DNS left unchanged".into());
        shared.set_enforcement(if enforcer.is_some() {
            EnforcementStatus::with_all(why)
        } else {
            EnforcementStatus::with_all(unavailable)
        });
        return;
    }
    let Some(enf) = enforcer else {
        shared.set_enforcement(EnforcementStatus::with_all(unavailable));
        return;
    };
    if upstream_addrs.is_empty() {
        let why = ComponentState::Failed("no upstream DNS known; system DNS left unchanged".into());
        shared.set_enforcement(EnforcementStatus::with_all(why));
        return;
    }

    // Explicitly configured upstreams are never replaced; discovered ones follow network changes.
    let track_discovered = configured_empty;
    let listening = Listening { v4, v6 };
    let first = {
        let enf = Arc::clone(&enf);
        run_blocking(move || {
            enf.lock()
                .unwrap_or_else(|e| e.into_inner())
                .reconcile(listening)
        })
        .await
    };
    if let Some(out) = first {
        apply_outcome(&shared, &filter, out, track_discovered);
    }
    agent.enforcer = Some(Arc::clone(&enf));

    let interval = opts.watchdog_interval;
    let mut stop = watchdog_rx;
    let wd_shared = Arc::clone(&shared);
    agent.watchdog = Some(tokio::spawn(async move {
        loop {
            tokio::select! {
                () = tokio::time::sleep(interval) => {
                    let enf = Arc::clone(&enf);
                    if let Some(out) = run_blocking(move || enf.lock().unwrap_or_else(|e| e.into_inner()).reconcile(listening)).await {
                        apply_outcome(&wd_shared, &filter, out, track_discovered);
                    }
                }
                _ = stop.changed() => break,
            }
        }
    }));
}

fn apply_outcome(
    shared: &Arc<Shared>,
    filter: &Arc<DnsFilter<UdpTcpUpstream, Arc<Shared>>>,
    out: crate::enforce::ReconcileOutcome,
    track_discovered: bool,
) {
    if track_discovered && !out.upstreams.is_empty() {
        let addrs: Vec<SocketAddr> = out
            .upstreams
            .iter()
            .map(|ip| SocketAddr::new(*ip, 53))
            .collect();
        if filter.upstream().servers() != addrs {
            filter.upstream().set_servers(addrs.clone());
            shared.set_upstreams(addrs.iter().map(|a| a.ip().to_string()).collect());
        }
    }
    for (name, c) in [
        ("system DNS", &out.status.system_dns),
        ("firewall", &out.status.firewall),
        ("browser policies", &out.status.browser_policies),
    ] {
        if let ComponentState::Failed(why) = c {
            tracing::error!("enforcement {name}: {why}");
        }
    }
    shared.set_enforcement(out.status);
}
