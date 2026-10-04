//! Agent lifecycle: load configuration, load rules, start IPC, shut down.
//!
//! Fail-safe policy (tested): a broken component never prevents the agent from
//! starting; it is skipped, logged and reported as `degraded` with a reason.
//! - invalid/unreadable config  -> built-in defaults (strict)
//! - database cannot be opened  -> custom lists unavailable
//! - global list missing/invalid -> no global blocklist
//!
//! The agent only refuses to start if the IPC endpoint cannot be bound.

use crate::config::{load_config_file, AppConfig};
use crate::ipc::{self, IpcEndpoint};
use crate::paths::DataDirs;
use crate::rules::{load_global_list_file, RuleEngine};
use crate::state::{GlobalListInfo, Shared};
use crate::storage::{Database, ListKind};
use anyhow::Context;
use std::sync::Arc;
use tokio::sync::watch;
use tokio::task::JoinHandle;

pub struct AgentOptions {
    pub dirs: DataDirs,
    pub endpoint: IpcEndpoint,
}

pub struct RunningAgent {
    shared: Arc<Shared>,
    shutdown: watch::Sender<bool>,
    server: JoinHandle<()>,
}

impl RunningAgent {
    pub fn shared(&self) -> Arc<Shared> {
        Arc::clone(&self.shared)
    }

    /// Stops accepting IPC clients and waits for the server task to finish.
    pub async fn shutdown(self) {
        self.shared.set_stopping();
        let _ = self.shutdown.send(true);
        let _ = self.server.await;
        tracing::info!("agent stopped");
    }
}

pub async fn start(opts: AgentOptions) -> anyhow::Result<RunningAgent> {
    let dirs = &opts.dirs;
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

    let shared = Arc::new(Shared::new(engine, config, global_info, degraded));
    let (tx, rx) = watch::channel(false);
    let server = ipc::bind(&opts.endpoint, Arc::clone(&shared), rx)
        .await
        .with_context(|| format!("cannot bind IPC endpoint {}", opts.endpoint))?;

    let state = shared.agent_state();
    tracing::info!(
        "agent ready (state: {state:?}); network filtering not implemented in this version"
    );
    Ok(RunningAgent {
        shared,
        shutdown: tx,
        server,
    })
}
