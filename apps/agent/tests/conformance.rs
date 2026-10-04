//! Runs the shared vectors (also used by the TypeScript tests) against the Rust implementation.

use savinggrace_agent::config::InvalidInputPolicy;
use savinggrace_agent::domain::{
    matches_domain, normalize_hostname, validate_rule_domain, DomainRuleEntry,
};
use savinggrace_agent::rules::{Action, RuleEngine, RuleType};
use serde_json::Value;

fn vectors() -> Value {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../tests/conformance/domain-vectors.json"
    );
    serde_json::from_str(&std::fs::read_to_string(path).expect("vectors file")).expect("valid json")
}

fn entries(v: &Value) -> Vec<DomainRuleEntry> {
    v.as_array()
        .unwrap()
        .iter()
        .map(|e| match e {
            Value::String(s) => DomainRuleEntry {
                domain: s.clone(),
                include_subdomains: true,
                category: None,
            },
            o => serde_json::from_value(o.clone()).unwrap(),
        })
        .collect()
}

#[test]
fn normalize_vectors() {
    let v = vectors();
    for case in v["normalize"].as_array().unwrap() {
        let input = case[0].as_str().unwrap();
        let expected = case[1].as_str().map(str::to_string);
        assert_eq!(normalize_hostname(input), expected, "normalize {input:?}");
    }
}

#[test]
fn match_vectors() {
    let v = vectors();
    for case in v["match"].as_array().unwrap() {
        let (h, r, sub, exp) = (
            case[0].as_str().unwrap(),
            case[1].as_str().unwrap(),
            case[2].as_bool().unwrap(),
            case[3].as_bool().unwrap(),
        );
        assert_eq!(
            matches_domain(h, r, sub),
            exp,
            "match {h:?} vs {r:?} sub={sub}"
        );
    }
}

#[test]
fn validate_rule_vectors() {
    let v = vectors();
    for case in v["validateRule"].as_array().unwrap() {
        let input = case[0].as_str().unwrap();
        let got = validate_rule_domain(input, true);
        match case[1].as_array() {
            None => assert!(got.is_err(), "{input:?} should be rejected"),
            Some(exp) => {
                let ok = got.unwrap_or_else(|e| panic!("{input:?} rejected: {e}"));
                assert_eq!(ok.domain, exp[0].as_str().unwrap());
                assert_eq!(ok.include_subdomains, exp[1].as_bool().unwrap());
            }
        }
    }
}

#[test]
fn engine_vectors() {
    let v = vectors();
    for c in v["engine"].as_array().unwrap() {
        let engine = RuleEngine::new(
            &entries(&c["allow"]),
            &entries(&c["custom"]),
            &entries(&c["global"]),
            InvalidInputPolicy::Allow,
        )
        .unwrap();
        let d = engine.evaluate(c["target"].as_str().unwrap());
        let action = if c["action"] == "ALLOW" {
            Action::Allow
        } else {
            Action::Block
        };
        let rule_type = match c["ruleType"].as_str().unwrap() {
            "allowlist" => RuleType::Allowlist,
            "custom_blocklist" => RuleType::CustomBlocklist,
            "global_blocklist" => RuleType::GlobalBlocklist,
            "default" => RuleType::Default,
            "invalid_input" => RuleType::InvalidInput,
            other => panic!("unknown ruleType {other}"),
        };
        assert_eq!(
            (d.action, d.rule_type),
            (action, rule_type),
            "engine case {}",
            c["name"]
        );
    }
}
