//! Browser policies that stop browsers from bypassing the system resolver with
//! their own DNS-over-HTTPS. Registry locations follow each vendor's documented
//! policy paths (verified against vendor/community documentation in Phase 3
//! research; Brave's path should be re-checked on a machine with Brave installed).
//!
//! Visible side effect: browsers show "Managed by your organization".

use super::store::RestoreStore;
use serde::{Deserialize, Serialize};
use std::collections::btree_map::Entry;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PolicyValue {
    Str(String),
    Dword(u32),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicySpec {
    /// Key under HKEY_LOCAL_MACHINE.
    pub key: &'static str,
    pub name: &'static str,
    pub value: PolicyValue,
}

impl PolicySpec {
    pub fn id(&self) -> String {
        format!("{}\\{}", self.key, self.name)
    }
}

pub fn browser_policies() -> Vec<PolicySpec> {
    let off = |key: &'static str| PolicySpec {
        key,
        name: "DnsOverHttpsMode",
        value: PolicyValue::Str("off".into()),
    };
    vec![
        off(r"SOFTWARE\Policies\Google\Chrome"),
        off(r"SOFTWARE\Policies\Microsoft\Edge"),
        off(r"SOFTWARE\Policies\BraveSoftware\Brave"),
        PolicySpec {
            key: r"SOFTWARE\Policies\Mozilla\Firefox\DNSOverHTTPS",
            name: "Enabled",
            value: PolicyValue::Dword(0),
        },
        PolicySpec {
            key: r"SOFTWARE\Policies\Mozilla\Firefox\DNSOverHTTPS",
            name: "Locked",
            value: PolicyValue::Dword(1),
        },
    ]
}

/// Machine-wide policy storage (the Windows registry in production).
pub trait PolicyStore {
    fn get(&self, key: &str, name: &str) -> Result<Option<PolicyValue>, String>;
    fn set(&self, key: &str, name: &str, value: &PolicyValue) -> Result<(), String>;
    fn delete(&self, key: &str, name: &str) -> Result<(), String>;
}

pub struct PolicyEnforcer<P: PolicyStore> {
    store: P,
    specs: Vec<PolicySpec>,
}

pub struct PolicyReport {
    pub tamper_events: u64,
    pub error: Option<String>,
}

impl<P: PolicyStore> PolicyEnforcer<P> {
    pub fn new(store: P) -> Self {
        Self {
            store,
            specs: browser_policies(),
        }
    }

    /// Writes any missing or altered policy. The first time a value is touched its
    /// previous content is recorded (and persisted) so it can be restored later.
    pub fn reconcile(&self, restore: &mut RestoreStore) -> PolicyReport {
        let mut tamper = 0;
        let mut errors = Vec::new();
        for spec in &self.specs {
            let current = match self.store.get(spec.key, spec.name) {
                Ok(c) => c,
                Err(e) => {
                    errors.push(format!("{}: {e}", spec.id()));
                    continue;
                }
            };
            if current.as_ref() == Some(&spec.value) {
                // Identical value already present. If it is not recorded as ours it was
                // set by someone else; keep it as the "original" so restore leaves it alone.
                restore.state.policies.entry(spec.id()).or_insert(current);
                continue;
            }
            match restore.state.policies.entry(spec.id()) {
                Entry::Occupied(_) => tamper += 1,
                Entry::Vacant(v) => {
                    v.insert(current);
                }
            }
            if let Err(e) = restore
                .save()
                .and_then(|()| self.store.set(spec.key, spec.name, &spec.value))
            {
                errors.push(format!("{}: {e}", spec.id()));
            }
        }
        PolicyReport {
            tamper_events: tamper,
            error: (!errors.is_empty()).then(|| errors.join("; ")),
        }
    }

    /// Puts every recorded value back (or deletes what did not exist before).
    pub fn restore(&self, restore: &mut RestoreStore) -> Vec<String> {
        let mut errors = Vec::new();
        for spec in &self.specs {
            let Some(prior) = restore.state.policies.get(&spec.id()).cloned() else {
                continue;
            };
            let r = match &prior {
                Some(v) => self.store.set(spec.key, spec.name, v),
                None => self.store.delete(spec.key, spec.name),
            };
            match r {
                Ok(()) => {
                    restore.state.policies.remove(&spec.id());
                }
                Err(e) => errors.push(format!("{}: {e}", spec.id())),
            }
        }
        if let Err(e) = restore.save() {
            errors.push(e);
        }
        errors
    }
}

#[cfg(test)]
pub(crate) mod fake {
    use super::*;
    use std::cell::RefCell;
    use std::collections::HashMap;

    #[derive(Default)]
    pub struct MemPolicies(pub RefCell<HashMap<(String, String), PolicyValue>>);

    impl PolicyStore for MemPolicies {
        fn get(&self, key: &str, name: &str) -> Result<Option<PolicyValue>, String> {
            Ok(self.0.borrow().get(&(key.into(), name.into())).cloned())
        }
        fn set(&self, key: &str, name: &str, v: &PolicyValue) -> Result<(), String> {
            self.0
                .borrow_mut()
                .insert((key.into(), name.into()), v.clone());
            Ok(())
        }
        fn delete(&self, key: &str, name: &str) -> Result<(), String> {
            self.0.borrow_mut().remove(&(key.into(), name.into()));
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::fake::MemPolicies;
    use super::*;

    fn store() -> (tempfile::TempDir, RestoreStore) {
        let d = tempfile::tempdir().unwrap();
        let (s, _) = RestoreStore::open(&d.path().join("s.json"));
        (d, s)
    }

    #[test]
    fn covers_the_four_browsers_and_turns_doh_off() {
        let p = browser_policies();
        let keys: Vec<_> = p.iter().map(|s| s.key).collect();
        for needle in [
            "Google\\Chrome",
            "Microsoft\\Edge",
            "BraveSoftware\\Brave",
            "Mozilla\\Firefox\\DNSOverHTTPS",
        ] {
            assert!(keys.iter().any(|k| k.contains(needle)), "missing {needle}");
        }
        for s in &p {
            assert!(s.key.starts_with(r"SOFTWARE\Policies\"));
            assert!(
                s.value == PolicyValue::Str("off".into())
                    || (s.name == "Enabled" && s.value == PolicyValue::Dword(0))
                    || (s.name == "Locked" && s.value == PolicyValue::Dword(1)),
                "{} would not disable DoH",
                s.id()
            );
        }
        let ids: std::collections::HashSet<_> = p.iter().map(PolicySpec::id).collect();
        assert_eq!(ids.len(), p.len());
    }

    #[test]
    fn applies_then_restores_to_exactly_the_prior_state() {
        let (_d, mut rs) = store();
        let mem = MemPolicies::default();
        // Pre-existing admin policy that must survive.
        mem.set(
            r"SOFTWARE\Policies\Google\Chrome",
            "DnsOverHttpsMode",
            &PolicyValue::Str("secure".into()),
        )
        .unwrap();
        let e = PolicyEnforcer::new(mem);
        let r = e.reconcile(&mut rs);
        assert!(r.error.is_none() && r.tamper_events == 0);
        assert_eq!(
            e.store
                .get(r"SOFTWARE\Policies\Google\Chrome", "DnsOverHttpsMode")
                .unwrap(),
            Some(PolicyValue::Str("off".into()))
        );
        assert_eq!(
            e.store
                .get(r"SOFTWARE\Policies\Mozilla\Firefox\DNSOverHTTPS", "Locked")
                .unwrap(),
            Some(PolicyValue::Dword(1))
        );

        assert!(e.restore(&mut rs).is_empty());
        assert_eq!(
            e.store
                .get(r"SOFTWARE\Policies\Google\Chrome", "DnsOverHttpsMode")
                .unwrap(),
            Some(PolicyValue::Str("secure".into()))
        );
        assert_eq!(
            e.store
                .get(r"SOFTWARE\Policies\Microsoft\Edge", "DnsOverHttpsMode")
                .unwrap(),
            None
        );
        assert!(rs.state.policies.is_empty());
    }

    #[test]
    fn detects_and_repairs_tampering_without_losing_the_original() {
        let (_d, mut rs) = store();
        let e = PolicyEnforcer::new(MemPolicies::default());
        e.reconcile(&mut rs);
        e.store
            .set(
                r"SOFTWARE\Policies\Microsoft\Edge",
                "DnsOverHttpsMode",
                &PolicyValue::Str("secure".into()),
            )
            .unwrap();
        e.store
            .delete(r"SOFTWARE\Policies\Mozilla\Firefox\DNSOverHTTPS", "Locked")
            .unwrap();
        let r = e.reconcile(&mut rs);
        assert_eq!(r.tamper_events, 2);
        assert_eq!(
            e.store
                .get(r"SOFTWARE\Policies\Microsoft\Edge", "DnsOverHttpsMode")
                .unwrap(),
            Some(PolicyValue::Str("off".into()))
        );
        // The "original" recorded for Edge is still "did not exist", not the tampered value.
        e.restore(&mut rs);
        assert_eq!(
            e.store
                .get(r"SOFTWARE\Policies\Microsoft\Edge", "DnsOverHttpsMode")
                .unwrap(),
            None
        );
    }

    #[test]
    fn restart_with_state_does_not_treat_our_values_as_original() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("s.json");
        let mem = MemPolicies::default();
        let (mut rs, _) = RestoreStore::open(&p);
        let e = PolicyEnforcer {
            store: mem,
            specs: browser_policies(),
        };
        e.reconcile(&mut rs);
        // "Process restart": new RestoreStore from disk, same registry.
        let (mut rs2, _) = RestoreStore::open(&p);
        let r = e.reconcile(&mut rs2);
        assert_eq!(r.tamper_events, 0);
        e.restore(&mut rs2);
        assert_eq!(
            e.store
                .get(r"SOFTWARE\Policies\Google\Chrome", "DnsOverHttpsMode")
                .unwrap(),
            None
        );
    }
}
