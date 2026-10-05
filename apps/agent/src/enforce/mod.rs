//! System-level enforcement: makes the local resolver unavoidable.
//!
//! Three cooperating mechanisms (see ADR 007):
//!  1. adapter DNS settings point at the agent's resolver (`dns_redirect`),
//!  2. firewall filters forbid every other DNS path (`firewall`),
//!  3. browser policies turn off the browsers' private DoH (`browser_policy`).
//!
//! `Enforcer` orchestrates them with explicit ordering rules that protect the
//! user from a self-inflicted outage. The Windows implementations live in `windows`.

pub mod browser_policy;
pub mod dns_redirect;
pub mod firewall;
pub mod guid;
pub mod store;
#[cfg(windows)]
pub mod windows;

use browser_policy::{PolicyEnforcer, PolicyStore};
use dns_redirect::{DnsRedirector, Listening, SystemDns};
use firewall::{build_filter_specs, bundled_doh_addresses, FilterSpec, Firewall};
use serde::Serialize;
use std::net::IpAddr;
use store::RestoreStore;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "state", content = "detail", rename_all = "snake_case")]
pub enum ComponentState {
    /// Turned off by configuration.
    Disabled,
    /// Not available on this platform.
    Unsupported,
    Applied,
    Failed(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EnforcementStatus {
    pub system_dns: ComponentState,
    pub firewall: ComponentState,
    pub browser_policies: ComponentState,
    /// Times a protected setting was found changed and put back (this run).
    pub tamper_events: u64,
}

impl EnforcementStatus {
    pub fn with_all(state: ComponentState) -> Self {
        Self {
            system_dns: state.clone(),
            firewall: state.clone(),
            browser_policies: state,
            tamper_events: 0,
        }
    }
}

pub struct ReconcileOutcome {
    pub status: EnforcementStatus,
    /// Current upstream resolvers for the local resolver to use.
    pub upstreams: Vec<IpAddr>,
}

/// What the agent needs from an enforcement backend (real Windows one, or a test double).
pub trait PlatformEnforcer: Send {
    /// The system's own DNS servers, read without changing anything.
    fn discover_upstreams(&mut self) -> Vec<IpAddr>;
    /// Applies / repairs everything. Only call once the resolver is accepting queries.
    fn reconcile(&mut self, listening: Listening) -> ReconcileOutcome;
    /// Undoes everything (clean stop). Returns problems, empty on full success.
    fn restore(&mut self) -> Vec<String>;
}

pub struct Enforcer<S: SystemDns, F: Firewall, P: PolicyStore> {
    redirector: DnsRedirector<S>,
    firewall: F,
    policies: PolicyEnforcer<P>,
    store: RestoreStore,
    specs: Vec<FilterSpec>,
    tamper_total: u64,
    firewall_applied: bool,
}

impl<S: SystemDns, F: Firewall, P: PolicyStore> Enforcer<S, F, P> {
    pub fn new(sys: S, firewall: F, policies: P, store: RestoreStore) -> Self {
        Self {
            redirector: DnsRedirector::new(sys),
            firewall,
            policies: PolicyEnforcer::new(policies),
            store,
            specs: build_filter_specs(&bundled_doh_addresses()),
            tamper_total: 0,
            firewall_applied: false,
        }
    }
}

impl<S: SystemDns + Send, F: Firewall + Send, P: PolicyStore + Send> PlatformEnforcer
    for Enforcer<S, F, P>
{
    fn discover_upstreams(&mut self) -> Vec<IpAddr> {
        self.redirector.upstreams(&self.store)
    }

    fn reconcile(&mut self, listening: Listening) -> ReconcileOutcome {
        // 1. DNS first: while names already resolve through us, the firewall can safely shut the other paths.
        let rep = self.redirector.reconcile(&mut self.store, listening);
        self.tamper_total += rep.tamper_events;
        let system_dns = if rep.errors.is_empty() {
            ComponentState::Applied
        } else {
            ComponentState::Failed(rep.errors.join("; "))
        };

        // 2. Firewall only if DNS is really redirected; otherwise blocking port 53 would cut the machine off.
        let firewall = if system_dns != ComponentState::Applied {
            self.firewall_applied = false;
            ComponentState::Failed("not applied because system DNS is not redirected".into())
        } else if self.firewall_applied && self.firewall.verify() {
            ComponentState::Applied
        } else {
            if self.firewall_applied {
                self.tamper_total += 1; // filters vanished: something removed them
            }
            match self.firewall.apply(&self.specs) {
                Ok(()) => {
                    self.firewall_applied = true;
                    ComponentState::Applied
                }
                Err(e) => {
                    self.firewall_applied = false;
                    ComponentState::Failed(e)
                }
            }
        };

        // 3. Browser policies are independent of the other two.
        let pol = self.policies.reconcile(&mut self.store);
        self.tamper_total += pol.tamper_events;
        let browser_policies = pol
            .error
            .map_or(ComponentState::Applied, ComponentState::Failed);

        ReconcileOutcome {
            status: EnforcementStatus {
                system_dns,
                firewall,
                browser_policies,
                tamper_events: self.tamper_total,
            },
            upstreams: self.redirector.upstreams(&self.store),
        }
    }

    fn restore(&mut self) -> Vec<String> {
        let mut errors = Vec::new();
        // Reverse order: remove the firewall first so DNS never has a dead end while settings are put back.
        if let Err(e) = self.firewall.remove() {
            errors.push(format!("firewall: {e}"));
        }
        self.firewall_applied = false;
        errors.extend(self.redirector.restore(&mut self.store));
        errors.extend(self.policies.restore(&mut self.store));
        errors
    }
}

#[cfg(test)]
mod tests {
    use super::dns_redirect::fake::*;
    use super::*;
    use std::sync::{Arc, Mutex};

    #[derive(Default)]
    struct FakeFw {
        log: Arc<Mutex<Vec<String>>>,
        present: Arc<Mutex<bool>>,
        fail_apply: bool,
    }

    impl Firewall for FakeFw {
        fn apply(&mut self, specs: &[FilterSpec]) -> Result<(), String> {
            self.log
                .lock()
                .unwrap()
                .push(format!("fw.apply({})", specs.len()));
            if self.fail_apply {
                return Err("bfe not running".into());
            }
            *self.present.lock().unwrap() = true;
            Ok(())
        }
        fn verify(&self) -> bool {
            *self.present.lock().unwrap()
        }
        fn remove(&mut self) -> Result<(), String> {
            self.log.lock().unwrap().push("fw.remove".into());
            *self.present.lock().unwrap() = false;
            Ok(())
        }
    }

    /// Shares the fake system between the test and the enforcer.
    struct Shared(Arc<FakeSystem>, Arc<Mutex<Vec<String>>>);
    impl SystemDns for Shared {
        fn interfaces(&self) -> Result<Vec<dns_redirect::InterfaceDns>, String> {
            self.0.interfaces()
        }
        fn set_nameserver(&self, id: &str, v6: bool, s: &str) -> Result<(), String> {
            self.1.lock().unwrap().push(format!("dns.set({s})"));
            self.0.set_nameserver(id, v6, s)
        }
    }

    type TestEnforcer = Enforcer<Shared, FakeFw, browser_policy::fake::MemPolicies>;

    struct Fixture {
        _dir: tempfile::TempDir,
        sys: Arc<FakeSystem>,
        log: Arc<Mutex<Vec<String>>>,
        present: Arc<Mutex<bool>>,
        e: TestEnforcer,
    }

    fn fixture(fail_fw: bool) -> Fixture {
        let sys = Arc::new(FakeSystem::default());
        *sys.ifaces.lock().unwrap() = vec![iface("a", "", &["192.168.1.1"])];
        let log = Arc::new(Mutex::new(Vec::new()));
        let present = Arc::new(Mutex::new(false));
        let dir = tempfile::tempdir().unwrap();
        let (st, _) = RestoreStore::open(&dir.path().join("s.json"));
        let fw = FakeFw {
            log: Arc::clone(&log),
            present: Arc::clone(&present),
            fail_apply: fail_fw,
        };
        let e = Enforcer::new(
            Shared(Arc::clone(&sys), Arc::clone(&log)),
            fw,
            browser_policy::fake::MemPolicies::default(),
            st,
        );
        Fixture {
            _dir: dir,
            sys,
            log,
            present,
            e,
        }
    }

    const V4: Listening = Listening {
        v4: true,
        v6: false,
    };

    #[test]
    fn applies_dns_before_firewall_and_removes_firewall_before_dns() {
        let Fixture {
            sys,
            log,
            present: _p,
            mut e,
            _dir: _d,
        } = fixture(false);
        let out = e.reconcile(V4);
        assert_eq!(out.status.system_dns, ComponentState::Applied);
        assert_eq!(out.status.firewall, ComponentState::Applied);
        assert_eq!(out.status.browser_policies, ComponentState::Applied);
        assert_eq!(
            out.upstreams,
            vec!["192.168.1.1".parse::<IpAddr>().unwrap()]
        );
        {
            let l = log.lock().unwrap();
            let dns = l.iter().position(|x| x.starts_with("dns.set(127")).unwrap();
            let fw = l.iter().position(|x| x.starts_with("fw.apply")).unwrap();
            assert!(
                dns < fw,
                "DNS must be redirected before the firewall closes other paths: {l:?}"
            );
        }
        log.lock().unwrap().clear();
        assert!(e.restore().is_empty());
        let l = log.lock().unwrap();
        let rm = l.iter().position(|x| x == "fw.remove").unwrap();
        let dns = l.iter().position(|x| x.starts_with("dns.set(")).unwrap();
        assert!(
            rm < dns,
            "firewall must be removed before DNS is restored: {l:?}"
        );
        assert_eq!(sys.ifaces.lock().unwrap()[0].static_v4, "");
    }

    #[test]
    fn firewall_is_never_applied_when_dns_redirection_failed() {
        let Fixture {
            sys,
            log,
            present,
            mut e,
            _dir: _d,
        } = fixture(false);
        *sys.fail_set_for.lock().unwrap() = Some("a".into());
        let out = e.reconcile(V4);
        assert!(matches!(out.status.system_dns, ComponentState::Failed(_)));
        assert!(
            matches!(out.status.firewall, ComponentState::Failed(ref m) if m.contains("not applied"))
        );
        assert!(!log
            .lock()
            .unwrap()
            .iter()
            .any(|x| x.starts_with("fw.apply")));
        assert!(!*present.lock().unwrap());
        // Policies are independent and still applied.
        assert_eq!(out.status.browser_policies, ComponentState::Applied);
    }

    #[test]
    fn firewall_failure_is_reported_and_retried_next_cycle() {
        let Fixture {
            sys: _s,
            log,
            present: _p,
            mut e,
            _dir: _d,
        } = fixture(true);
        let out = e.reconcile(V4);
        assert_eq!(
            out.status.firewall,
            ComponentState::Failed("bfe not running".into())
        );
        e.reconcile(V4);
        assert_eq!(
            log.lock()
                .unwrap()
                .iter()
                .filter(|x| x.starts_with("fw.apply"))
                .count(),
            2
        );
    }

    #[test]
    fn removed_filters_are_reinstalled_and_counted_as_tampering() {
        let Fixture {
            sys: _s,
            log,
            present,
            mut e,
            _dir: _d,
        } = fixture(false);
        e.reconcile(V4);
        *present.lock().unwrap() = false; // someone deleted our filters
        let out = e.reconcile(V4);
        assert_eq!(out.status.firewall, ComponentState::Applied);
        assert_eq!(out.status.tamper_events, 1);
        assert_eq!(
            log.lock()
                .unwrap()
                .iter()
                .filter(|x| x.starts_with("fw.apply"))
                .count(),
            2
        );
        // Steady state does nothing.
        e.reconcile(V4);
        assert_eq!(
            log.lock()
                .unwrap()
                .iter()
                .filter(|x| x.starts_with("fw.apply"))
                .count(),
            2
        );
    }

    #[test]
    fn tamper_counter_accumulates_across_components() {
        let Fixture {
            sys,
            log: _l,
            present: _p,
            mut e,
            _dir: _d,
        } = fixture(false);
        e.reconcile(V4);
        sys.ifaces.lock().unwrap()[0].static_v4 = "8.8.8.8".into();
        assert_eq!(e.reconcile(V4).status.tamper_events, 1);
    }

    #[test]
    fn discover_upstreams_has_no_side_effects() {
        let Fixture {
            sys,
            log,
            present: _p,
            mut e,
            _dir: _d,
        } = fixture(false);
        assert_eq!(
            e.discover_upstreams(),
            vec!["192.168.1.1".parse::<IpAddr>().unwrap()]
        );
        assert!(log.lock().unwrap().is_empty());
        assert_eq!(sys.ifaces.lock().unwrap()[0].static_v4, "");
    }
}
