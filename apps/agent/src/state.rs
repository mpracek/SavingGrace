//! Shared, read-mostly agent state exposed over IPC.

use crate::config::AppConfig;
use crate::rules::RuleEngine;
use serde::Serialize;
use std::sync::{Arc, RwLock};
use std::time::Instant;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentState {
    Starting,
    /// Everything loaded as intended.
    Running,
    /// Running, but a component failed to load; see `degraded_reasons`.
    Degraded,
    Stopping,
}

/// Whether traffic is actually being filtered. The agent must never report
/// protection as active unless a filter really is. Phase 3 adds the real states.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FilteringStatus {
    NotImplemented,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct GlobalListInfo {
    pub count: usize,
    pub version: u64,
    pub updated: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RulesSummary {
    pub global_list: Option<GlobalListInfo>,
    pub custom_blocklist: usize,
    pub allowlist: usize,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConfigSummary {
    pub temporary_disable_enabled: bool,
    pub disable_challenge_word_count: u32,
    pub ui_language: crate::config::UiLanguage,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Status {
    pub version: &'static str,
    pub protocol_version: u32,
    pub agent_state: AgentState,
    pub degraded_reasons: Vec<String>,
    pub uptime_seconds: u64,
    pub network_filtering: FilteringStatus,
    pub rules: RulesSummary,
    pub config: ConfigSummary,
}

pub struct Shared {
    started: Instant,
    state: RwLock<AgentState>,
    degraded_reasons: Vec<String>,
    engine: Arc<RuleEngine>,
    config: AppConfig,
    global_list: Option<GlobalListInfo>,
}

impl Shared {
    pub fn new(
        engine: RuleEngine,
        config: AppConfig,
        global_list: Option<GlobalListInfo>,
        degraded_reasons: Vec<String>,
    ) -> Self {
        let state = if degraded_reasons.is_empty() {
            AgentState::Running
        } else {
            AgentState::Degraded
        };
        Self {
            started: Instant::now(),
            state: RwLock::new(state),
            degraded_reasons,
            engine: Arc::new(engine),
            config,
            global_list,
        }
    }

    pub fn engine(&self) -> Arc<RuleEngine> {
        Arc::clone(&self.engine)
    }

    pub fn agent_state(&self) -> AgentState {
        *self.state.read().unwrap_or_else(|e| e.into_inner())
    }

    pub fn set_stopping(&self) {
        *self.state.write().unwrap_or_else(|e| e.into_inner()) = AgentState::Stopping;
    }

    pub fn status(&self) -> Status {
        let (allow, custom, _global) = self.engine.counts();
        Status {
            version: crate::VERSION,
            protocol_version: crate::ipc::PROTOCOL_VERSION,
            agent_state: self.agent_state(),
            degraded_reasons: self.degraded_reasons.clone(),
            uptime_seconds: self.started.elapsed().as_secs(),
            network_filtering: FilteringStatus::NotImplemented,
            rules: RulesSummary {
                global_list: self.global_list.clone(),
                custom_blocklist: custom,
                allowlist: allow,
            },
            config: ConfigSummary {
                temporary_disable_enabled: self.config.temporary_disable_enabled,
                disable_challenge_word_count: self.config.disable_challenge_word_count,
                ui_language: self.config.ui_language,
            },
        }
    }
}
