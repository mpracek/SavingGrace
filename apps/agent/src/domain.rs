//! Hostname normalization and label-boundary domain matching.
//!
//! This is a port of `packages/domain-matcher` (TypeScript). Both implementations
//! are verified against the shared vectors in `tests/conformance/domain-vectors.json`.
//! Parsing is delegated to the WHATWG-compliant `url` crate so we agree with
//! browsers about what the host of a URL is.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use url::Url;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DomainRuleEntry {
    /// Normalized domain or IP literal.
    pub domain: String,
    /// Also cover every subdomain (never true for IP literals).
    pub include_subdomains: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub category: Option<String>,
}

const ALLOWED_SCHEMES: [&str; 5] = ["http", "https", "ws", "wss", "ftp"];

fn is_ipv4(host: &str) -> bool {
    let parts: Vec<&str> = host.split('.').collect();
    parts.len() == 4
        && parts
            .iter()
            .all(|p| !p.is_empty() && p.len() <= 3 && p.bytes().all(|b| b.is_ascii_digit()))
}

/// True for IPv4 dotted-quads and bracketed IPv6 literals (as returned by [`normalize_hostname`]).
pub fn is_ip_literal(host: &str) -> bool {
    (host.starts_with('[') && host.ends_with(']')) || is_ipv4(host)
}

fn has_scheme(s: &str) -> bool {
    match s.find("://") {
        Some(i) if i > 0 => {
            let scheme = &s[..i];
            let mut chars = scheme.chars();
            chars.next().is_some_and(|c| c.is_ascii_alphabetic())
                && chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.'))
        }
        _ => false,
    }
}

/// Turns a hostname, `host:port` or URL into a canonical hostname: lowercase,
/// punycode, one trailing dot removed, no port/userinfo/path. `None` if invalid.
/// Never panics.
pub fn normalize_hostname(input: &str) -> Option<String> {
    let s = input.trim();
    if s.is_empty() || s.len() > 2048 {
        return None;
    }
    // URL parsing silently strips tabs/newlines; reject them instead.
    if s.chars().any(|c| (c as u32) <= 0x20 || c as u32 == 0x7f) {
        return None;
    }
    let candidate = if has_scheme(s) {
        s.to_string()
    } else if s.starts_with("//") {
        format!("http:{s}")
    } else {
        format!("http://{s}")
    };
    let url = Url::parse(&candidate).ok()?;
    if !ALLOWED_SCHEMES.contains(&url.scheme()) {
        return None;
    }
    let mut host = url.host_str()?.to_ascii_lowercase();
    if host.starts_with('[') {
        return (host.ends_with(']') && host.len() > 2).then_some(host);
    }
    if host.ends_with('.') {
        host.pop();
    }
    if host.is_empty() || host.len() > 253 {
        return None;
    }
    for label in host.split('.') {
        let ok = !label.is_empty()
            && label.len() <= 63
            && label
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'-');
        if !ok {
            return None;
        }
    }
    Some(host)
}

/// A rule domain that passed validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidRuleDomain {
    pub domain: String,
    pub include_subdomains: bool,
}

/// Validates a domain a user wants to add to a list. Single-label names are
/// rejected (a rule must never cover a whole TLD); IP literals are exact-only.
pub fn validate_rule_domain(
    input: &str,
    include_subdomains: bool,
) -> Result<ValidRuleDomain, String> {
    let domain = normalize_hostname(input).ok_or_else(|| "Not a valid hostname.".to_string())?;
    if is_ip_literal(&domain) {
        return Ok(ValidRuleDomain {
            domain,
            include_subdomains: false,
        });
    }
    if !domain.contains('.') {
        return Err("A rule needs at least two labels (e.g. example.com).".to_string());
    }
    Ok(ValidRuleDomain {
        domain,
        include_subdomains,
    })
}

/// Label-boundary match of `host` against one rule.
pub fn matches_domain(host: &str, rule_domain: &str, include_subdomains: bool) -> bool {
    let (Some(h), Some(r)) = (normalize_hostname(host), normalize_hostname(rule_domain)) else {
        return false;
    };
    if h == r {
        return true;
    }
    if !include_subdomains || is_ip_literal(&h) || is_ip_literal(&r) {
        return false;
    }
    h.ends_with(&format!(".{r}"))
}

/// A set of domain rules with lookup in O(labels).
#[derive(Debug, Default, Clone)]
pub struct DomainSet {
    entries: HashMap<String, DomainRuleEntry>,
}

impl DomainSet {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Adds a rule. Duplicates merge (subdomain coverage wins, first category kept).
    pub fn add(&mut self, entry: &DomainRuleEntry) -> Result<(), String> {
        let v = validate_rule_domain(&entry.domain, entry.include_subdomains)
            .map_err(|e| format!("Invalid rule domain \"{}\": {e}", entry.domain))?;
        let merged = match self.entries.get(&v.domain) {
            Some(existing) => DomainRuleEntry {
                domain: v.domain.clone(),
                include_subdomains: existing.include_subdomains || v.include_subdomains,
                category: existing.category.clone().or_else(|| entry.category.clone()),
            },
            None => DomainRuleEntry {
                domain: v.domain.clone(),
                include_subdomains: v.include_subdomains,
                category: entry.category.clone(),
            },
        };
        self.entries.insert(v.domain, merged);
        Ok(())
    }

    pub fn remove(&mut self, domain: &str) -> bool {
        normalize_hostname(domain).is_some_and(|n| self.entries.remove(&n).is_some())
    }

    /// Most specific matching rule for a hostname/URL.
    pub fn matching(&self, target: &str) -> Option<&DomainRuleEntry> {
        normalize_hostname(target).and_then(|h| self.matching_normalized(&h))
    }

    /// Like [`matching`](Self::matching) but expects an already-normalized hostname.
    pub fn matching_normalized(&self, host: &str) -> Option<&DomainRuleEntry> {
        if let Some(e) = self.entries.get(host) {
            return Some(e);
        }
        if is_ip_literal(host) {
            return None;
        }
        let mut rest = host;
        while let Some(i) = rest.find('.') {
            rest = &rest[i + 1..];
            if let Some(e) = self.entries.get(rest) {
                if e.include_subdomains {
                    return Some(e);
                }
            }
        }
        None
    }
}
