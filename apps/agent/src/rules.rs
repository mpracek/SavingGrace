//! Rule engine: fixed priority allowlist > custom blocklist > global blocklist > default.
//! Port of `packages/rule-engine`. Classifiers are not part of the agent yet (Phase 11).

use crate::config::InvalidInputPolicy;
use crate::domain::{normalize_hostname, validate_rule_domain, DomainRuleEntry, DomainSet};
use serde::Serialize;
use serde_json::Value;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Action {
    Allow,
    Block,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RuleType {
    Allowlist,
    CustomBlocklist,
    GlobalBlocklist,
    Default,
    InvalidInput,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Decision {
    pub action: Action,
    pub rule_type: RuleType,
    pub matched_rule: Option<String>,
    pub hostname: Option<String>,
    pub category: Option<String>,
    pub warnings: Vec<String>,
}

/// Immutable once built; to change rules build a new engine and swap the `Arc`.
#[derive(Debug, Clone)]
pub struct RuleEngine {
    allow: DomainSet,
    custom: DomainSet,
    global: DomainSet,
    on_invalid: InvalidInputPolicy,
}

fn build_set(entries: &[DomainRuleEntry]) -> Result<DomainSet, String> {
    let mut set = DomainSet::new();
    for e in entries {
        set.add(e)?;
    }
    Ok(set)
}

impl RuleEngine {
    pub fn new(
        allowlist: &[DomainRuleEntry],
        custom_blocklist: &[DomainRuleEntry],
        global_blocklist: &[DomainRuleEntry],
        on_invalid: InvalidInputPolicy,
    ) -> Result<Self, String> {
        Ok(Self {
            allow: build_set(allowlist)?,
            custom: build_set(custom_blocklist)?,
            global: build_set(global_blocklist)?,
            on_invalid,
        })
    }

    pub fn counts(&self) -> (usize, usize, usize) {
        (self.allow.len(), self.custom.len(), self.global.len())
    }

    /// Evaluates a name taken straight from a DNS packet.
    ///
    /// Unlike [`evaluate`](Self::evaluate) this never runs the name through a URL
    /// parser: DNS labels may contain bytes such as `\\` or `@` that a URL parser
    /// would reinterpret (`x\\.bad.example` would parse as host `x`), which would
    /// let a hostile client hide a blocked name. Only lowercasing and removal of
    /// one trailing dot happen here; suffix matching is purely label-based.
    pub fn evaluate_dns_name(&self, name: &str) -> Decision {
        let lower = name.to_ascii_lowercase();
        let host = lower.strip_suffix('.').unwrap_or(&lower);
        if host.is_empty() {
            return self.default_decision(None);
        }
        self.decide_normalized(host)
    }

    fn default_decision(&self, host: Option<String>) -> Decision {
        Decision {
            action: Action::Allow,
            rule_type: RuleType::Default,
            matched_rule: None,
            hostname: host,
            category: None,
            warnings: vec![],
        }
    }

    fn decide_normalized(&self, host: &str) -> Decision {
        let stages = [
            (&self.allow, Action::Allow, RuleType::Allowlist),
            (&self.custom, Action::Block, RuleType::CustomBlocklist),
            (&self.global, Action::Block, RuleType::GlobalBlocklist),
        ];
        for (set, action, rule_type) in stages {
            if let Some(e) = set.matching_normalized(host) {
                return Decision {
                    action,
                    rule_type,
                    matched_rule: Some(e.domain.clone()),
                    hostname: Some(host.to_string()),
                    category: e.category.clone(),
                    warnings: vec![],
                };
            }
        }
        self.default_decision(Some(host.to_string()))
    }

    pub fn evaluate(&self, target: &str) -> Decision {
        let Some(host) = normalize_hostname(target) else {
            return Decision {
                action: match self.on_invalid {
                    InvalidInputPolicy::Block => Action::Block,
                    InvalidInputPolicy::Allow => Action::Allow,
                },
                rule_type: RuleType::InvalidInput,
                matched_rule: None,
                hostname: None,
                category: None,
                warnings: vec![],
            };
        };
        self.decide_normalized(&host)
    }
}

/// Parsed global adult-domain database.
#[derive(Debug, Clone)]
pub struct GlobalList {
    pub version: u64,
    pub updated: String,
    pub entries: Vec<DomainRuleEntry>,
}

#[derive(Debug, thiserror::Error)]
#[error("global list: {0}")]
pub struct GlobalListError(pub String);

fn err<T>(msg: impl Into<String>) -> Result<T, GlobalListError> {
    Err(GlobalListError(msg.into()))
}

fn is_iso_date(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() == 10
        && b.iter().enumerate().all(|(i, c)| {
            if i == 4 || i == 7 {
                *c == b'-'
            } else {
                c.is_ascii_digit()
            }
        })
}

/// Validates schema v1 (strings) or v2 (objects with category). Any invalid
/// entry rejects the whole file: a partially loaded list would silently weaken protection.
pub fn parse_global_list(raw: &Value) -> Result<GlobalList, GlobalListError> {
    let Some(obj) = raw.as_object() else {
        return err("list must be a JSON object");
    };
    let version = match obj.get("version").and_then(Value::as_u64) {
        Some(v @ (1 | 2)) => v,
        other => return err(format!("unsupported list version {other:?}")),
    };
    let updated = match obj.get("updated").and_then(Value::as_str) {
        Some(s) if is_iso_date(s) => s.to_string(),
        _ => return err("\"updated\" must be YYYY-MM-DD"),
    };
    let Some(domains) = obj.get("domains").and_then(Value::as_array) else {
        return err("\"domains\" must be an array");
    };
    let mut entries = Vec::with_capacity(domains.len());
    for (i, d) in domains.iter().enumerate() {
        let (domain, category) = if version == 1 {
            (d.as_str(), "adult".to_string())
        } else {
            let Some(o) = d.as_object() else {
                return err(format!("domains[{i}] must be an object"));
            };
            let category = match o.get("category") {
                None => "adult".to_string(),
                Some(Value::String(c)) if !c.is_empty() => c.clone(),
                Some(_) => return err(format!("domains[{i}].category invalid")),
            };
            (o.get("domain").and_then(Value::as_str), category)
        };
        let Some(domain) = domain else {
            return err(format!("domains[{i}] has no domain string"));
        };
        match validate_rule_domain(domain, true) {
            Ok(v) => entries.push(DomainRuleEntry {
                domain: v.domain,
                include_subdomains: v.include_subdomains,
                category: Some(category),
            }),
            Err(e) => return err(format!("domains[{i}] \"{domain}\": {e}")),
        }
    }
    Ok(GlobalList {
        version,
        updated,
        entries,
    })
}

pub fn load_global_list_file(path: &std::path::Path) -> Result<GlobalList, GlobalListError> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| GlobalListError(format!("cannot read {}: {e}", path.display())))?;
    let json: Value = serde_json::from_str(&text)
        .map_err(|e| GlobalListError(format!("{} is not valid JSON: {e}", path.display())))?;
    parse_global_list(&json)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn parses_v1_and_v2() {
        let v1 =
            parse_global_list(&json!({"version":1,"updated":"2026-01-01","domains":["A.com"]}))
                .unwrap();
        assert_eq!(v1.entries[0].domain, "a.com");
        assert_eq!(v1.entries[0].category.as_deref(), Some("adult"));
        let v2 = parse_global_list(&json!({"version":2,"updated":"2026-01-01","domains":[{"domain":"b.com","category":"x"}]})).unwrap();
        assert_eq!(v2.entries[0].category.as_deref(), Some("x"));
    }

    #[test]
    fn rejects_invalid_lists() {
        for bad in [
            json!({"version":3,"updated":"2026-01-01","domains":[]}),
            json!({"version":1,"updated":"yesterday","domains":[]}),
            json!({"version":1,"updated":"2026-01-01","domains":["com"]}),
            json!({"version":1,"updated":"2026-01-01","domains":[42]}),
            json!({"version":2,"updated":"2026-01-01","domains":["a.com"]}),
            json!(null),
        ] {
            assert!(parse_global_list(&bad).is_err(), "should reject {bad}");
        }
    }

    #[test]
    fn invalid_policy_block_is_honoured() {
        let e = RuleEngine::new(&[], &[], &[], InvalidInputPolicy::Block).unwrap();
        let d = e.evaluate("");
        assert_eq!(
            (d.action, d.rule_type),
            (Action::Block, RuleType::InvalidInput)
        );
    }

    #[test]
    fn the_shipped_global_list_is_valid() {
        let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../data/adult-domains/domains.json");
        let list = load_global_list_file(&p).unwrap();
        assert!(!list.entries.is_empty());
    }
}
