//! Strict configuration parsing. Port of `packages/configuration`.
//! Unknown keys and out-of-range values are errors, never silently ignored.

use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum InvalidInputPolicy {
    Allow,
    Block,
}

/// Language of the Admin UI.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum UiLanguage {
    #[serde(rename = "sl")]
    Slovenian,
    #[serde(rename = "en")]
    English,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields, default)]
pub struct AppConfig {
    pub temporary_disable_enabled: bool,
    pub disable_challenge_word_count: u32,
    pub disable_durations_minutes: Vec<u32>,
    pub disable_challenge_max_failed_attempts: u32,
    pub attempt_retention_days: u32,
    pub on_invalid_input: InvalidInputPolicy,
    pub ui_language: UiLanguage,
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            temporary_disable_enabled: true,
            disable_challenge_word_count: 50,
            disable_durations_minutes: vec![5, 15, 30, 60],
            disable_challenge_max_failed_attempts: 3,
            attempt_retention_days: 90,
            on_invalid_input: InvalidInputPolicy::Allow,
            ui_language: UiLanguage::Slovenian,
        }
    }
}

#[derive(Debug, thiserror::Error)]
#[error("invalid configuration: {}", .problems.join("; "))]
pub struct ConfigError {
    pub problems: Vec<String>,
}

fn fail<T>(msg: impl Into<String>) -> Result<T, ConfigError> {
    Err(ConfigError {
        problems: vec![msg.into()],
    })
}

/// Parses and validates a JSON config; missing keys take the defaults.
pub fn parse_config(json: &str) -> Result<AppConfig, ConfigError> {
    let value: serde_json::Value = match serde_json::from_str(json) {
        Ok(v) => v,
        Err(_) => return fail("configuration is not valid JSON"),
    };
    if !value.is_object() {
        return fail("configuration must be a JSON object");
    }
    let mut cfg: AppConfig = match serde_json::from_value(value) {
        Ok(c) => c,
        Err(e) => return fail(e.to_string()),
    };

    let mut problems = Vec::new();
    if !(10..=100).contains(&cfg.disable_challenge_word_count) {
        problems.push("disableChallengeWordCount must be an integer 10..100".to_string());
    }
    let d = &cfg.disable_durations_minutes;
    if d.is_empty() || d.iter().any(|m| !(1..=240).contains(m)) {
        problems.push(
            "disableDurationsMinutes must be a non-empty array of integers 1..240".to_string(),
        );
    }
    if !(1..=20).contains(&cfg.disable_challenge_max_failed_attempts) {
        problems.push("disableChallengeMaxFailedAttempts must be an integer 1..20".to_string());
    }
    if !(1..=3650).contains(&cfg.attempt_retention_days) {
        problems.push("attemptRetentionDays must be an integer 1..3650".to_string());
    }
    if !problems.is_empty() {
        return Err(ConfigError { problems });
    }
    cfg.disable_durations_minutes.sort_unstable();
    cfg.disable_durations_minutes.dedup();
    Ok(cfg)
}

/// A missing file yields the defaults; an unreadable or invalid file is an error
/// (the caller decides the fail-safe behaviour).
pub fn load_config_file(path: &Path) -> Result<AppConfig, ConfigError> {
    match std::fs::read_to_string(path) {
        Ok(text) => parse_config(&text),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(AppConfig::default()),
        Err(e) => fail(format!("cannot read {}: {e}", path.display())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_match_the_specification() {
        let c = AppConfig::default();
        assert!(c.temporary_disable_enabled);
        assert_eq!(c.disable_challenge_word_count, 50);
        assert_eq!(c.disable_durations_minutes, vec![5, 15, 30, 60]);
        assert_eq!(c.ui_language, UiLanguage::Slovenian);
        assert_eq!(parse_config("{}").unwrap(), c);
    }

    #[test]
    fn partial_config_merges_and_normalizes() {
        let c = parse_config(r#"{"disableChallengeWordCount":75,"disableDurationsMinutes":[30,5,5],"uiLanguage":"en"}"#).unwrap();
        assert_eq!(c.disable_challenge_word_count, 75);
        assert_eq!(c.disable_durations_minutes, vec![5, 30]);
        assert_eq!(c.ui_language, UiLanguage::English);
    }

    #[test]
    fn rejects_invalid_configs() {
        for bad in [
            r#"{"disableChallengeWordCount":9}"#,
            r#"{"disableChallengeWordCount":101}"#,
            r#"{"disableChallengeWordCount":50.5}"#,
            r#"{"disableChallengeWordCount":"50"}"#,
            r#"{"temporaryDisableEnabled":"yes"}"#,
            r#"{"disableDurationsMinutes":[]}"#,
            r#"{"disableDurationsMinutes":[0]}"#,
            r#"{"disableDurationsMinutes":[100000]}"#,
            r#"{"onInvalidInput":"maybe"}"#,
            r#"{"uiLanguage":"de"}"#,
            r#"{"unknownKey":1}"#,
            "[]",
            "null",
            "{ not json",
        ] {
            assert!(parse_config(bad).is_err(), "should reject {bad}");
        }
    }

    #[test]
    fn missing_file_gives_defaults_but_broken_file_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(
            load_config_file(&dir.path().join("nope.json")).unwrap(),
            AppConfig::default()
        );
        let p = dir.path().join("bad.json");
        std::fs::write(&p, "{ nope").unwrap();
        assert!(load_config_file(&p).is_err());
    }
}
