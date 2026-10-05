//! Shared, read-mostly agent state exposed over IPC.

use crate::config::AppConfig;
use crate::dns::{DnsStats, DnsStatsSnapshot};
use crate::enforce::{ComponentState, EnforcementStatus};
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

/// Whether traffic is actually being filtered. The agent never reports more than is true.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FilteringStatus {
    /// The resolver is not accepting queries: nothing is filtered.
    NotActive,
    /// The resolver works, but nothing forces programs to use it (development, or enforcement off/unsupported).
    DnsOnly,
    /// Resolver plus some, but not all, enforcement components.
    Partial,
    /// Resolver, system DNS redirection, firewall filters and browser policies are all in place.
    Enforced,
}

pub fn compute_filtering(resolver_listening: bool, e: &EnforcementStatus) -> FilteringStatus {
    if !resolver_listening {
        return FilteringStatus::NotActive;
    }
    let parts = [&e.system_dns, &e.firewall, &e.browser_policies];
    let applied = parts
        .iter()
        .filter(|c| ***c == ComponentState::Applied)
        .count();
    match applied {
        3 => FilteringStatus::Enforced,
        0 => FilteringStatus::DnsOnly,
        _ => FilteringStatus::Partial,
    }
}

#[derive(Debug, Clone, Default, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct DnsRuntime {
    pub enabled: bool,
    pub listening: Vec<String>,
    pub failed: Vec<String>,
    pub upstreams: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DnsStatus {
    #[serde(flatten)]
    pub runtime: DnsRuntime,
    pub stats: DnsStatsSnapshot,
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
    pub dns: DnsStatus,
    pub enforcement: EnforcementStatus,
    pub rules: RulesSummary,
    pub config: ConfigSummary,
}

struct Runtime {
    dns: DnsRuntime,
    enforcement: EnforcementStatus,
}

pub struct Shared {
    started: Instant,
    state: RwLock<AgentState>,
    degraded_reasons: RwLock<Vec<String>>,
    engine: Arc<RuleEngine>,
    config: AppConfig,
    global_list: Option<GlobalListInfo>,
    dns_stats: Arc<DnsStats>,
    runtime: RwLock<Runtime>,
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
            degraded_reasons: RwLock::new(degraded_reasons),
            engine: Arc::new(engine),
            config,
            global_list,
            dns_stats: Arc::new(DnsStats::default()),
            runtime: RwLock::new(Runtime {
                dns: DnsRuntime::default(),
                enforcement: EnforcementStatus::with_all(ComponentState::Disabled),
            }),
        }
    }

    pub fn dns_stats(&self) -> Arc<DnsStats> {
        Arc::clone(&self.dns_stats)
    }

    /// Records a component failure; the agent keeps running but reports `degraded`.
    pub fn add_degraded(&self, reason: &str) {
        let mut r = self
            .degraded_reasons
            .write()
            .unwrap_or_else(|e| e.into_inner());
        if !r.iter().any(|x| x == reason) {
            r.push(reason.to_string());
        }
        let mut st = self.state.write().unwrap_or_else(|e| e.into_inner());
        if *st == AgentState::Running {
            *st = AgentState::Degraded;
        }
    }

    pub fn set_dns_runtime(&self, dns: DnsRuntime) {
        self.runtime.write().unwrap_or_else(|e| e.into_inner()).dns = dns;
    }

    pub fn set_upstreams(&self, upstreams: Vec<String>) {
        self.runtime
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .dns
            .upstreams = upstreams;
    }

    pub fn set_enforcement(&self, e: EnforcementStatus) {
        self.runtime
            .write()
            .unwrap_or_else(|x| x.into_inner())
            .enforcement = e;
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
        let rt = self.runtime.read().unwrap_or_else(|e| e.into_inner());
        let network_filtering = compute_filtering(!rt.dns.listening.is_empty(), &rt.enforcement);
        Status {
            version: crate::VERSION,
            protocol_version: crate::ipc::PROTOCOL_VERSION,
            agent_state: self.agent_state(),
            degraded_reasons: self
                .degraded_reasons
                .read()
                .unwrap_or_else(|e| e.into_inner())
                .clone(),
            uptime_seconds: self.started.elapsed().as_secs(),
            network_filtering,
            dns: DnsStatus {
                runtime: rt.dns.clone(),
                stats: self.dns_stats.snapshot(),
            },
            enforcement: rt.enforcement.clone(),
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

#[cfg(test)]
mod tests {
    use super::*;

    fn st(a: ComponentState, b: ComponentState, c: ComponentState) -> EnforcementStatus {
        EnforcementStatus {
            system_dns: a,
            firewall: b,
            browser_policies: c,
            tamper_events: 0,
        }
    }
    use ComponentState::{Applied, Disabled, Failed, Unsupported};

    #[test]
    fn filtering_is_enforced_only_when_everything_is_applied() {
        assert_eq!(
            compute_filtering(true, &st(Applied, Applied, Applied)),
            FilteringStatus::Enforced
        );
        for partial in [
            st(Applied, Applied, Failed("x".into())),
            st(Applied, Failed("x".into()), Applied),
            st(Failed("x".into()), Applied, Applied),
            st(Applied, Disabled, Disabled),
        ] {
            assert_eq!(compute_filtering(true, &partial), FilteringStatus::Partial);
        }
    }

    #[test]
    fn filtering_without_enforcement_is_dns_only_and_without_resolver_is_not_active() {
        assert_eq!(
            compute_filtering(true, &EnforcementStatus::with_all(Unsupported)),
            FilteringStatus::DnsOnly
        );
        assert_eq!(
            compute_filtering(true, &EnforcementStatus::with_all(Disabled)),
            FilteringStatus::DnsOnly
        );
        // Even if every enforcement part claims success, no listening resolver means nothing is filtered.
        assert_eq!(
            compute_filtering(false, &st(Applied, Applied, Applied)),
            FilteringStatus::NotActive
        );
    }
}
