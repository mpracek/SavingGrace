//! Persistent record of what the agent changed on the system, so it can put
//! everything back (clean stop, uninstall) and never mistakes its own change
//! for the user's original setting after a restart.

use super::browser_policy::PolicyValue;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IfaceOriginal {
    /// Static IPv4 name servers before we changed them; empty = automatic (DHCP).
    pub original_v4: String,
    /// Static IPv6 name servers; `None` = we never touched the IPv6 setting.
    pub original_v6: Option<String>,
    /// The adapter already pointed at loopback when we first saw it (crash leftovers);
    /// the true original is unknown and "automatic" is used on restore.
    pub orphaned: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EnforcementState {
    pub version: u32,
    pub interfaces: BTreeMap<String, IfaceOriginal>,
    /// "<key>\\<value name>" -> value before we wrote ours (`None` = did not exist).
    pub policies: BTreeMap<String, Option<PolicyValue>>,
}

pub struct RestoreStore {
    path: PathBuf,
    pub state: EnforcementState,
}

impl RestoreStore {
    /// Loads the store. A corrupt file is moved aside (never silently discarded)
    /// and the returned warning says so.
    pub fn open(path: &Path) -> (Self, Option<String>) {
        let mut warning = None;
        let state = match std::fs::read_to_string(path) {
            Ok(text) => match serde_json::from_str::<EnforcementState>(&text) {
                Ok(s) => s,
                Err(e) => {
                    let aside = path.with_extension("corrupt");
                    let _ = std::fs::rename(path, &aside);
                    warning = Some(format!(
                        "restore state was unreadable ({e}); moved to {}",
                        aside.display()
                    ));
                    EnforcementState::default()
                }
            },
            Err(_) => EnforcementState::default(),
        };
        (
            Self {
                path: path.to_path_buf(),
                state: EnforcementState {
                    version: 1,
                    ..state
                },
            },
            warning,
        )
    }

    /// Atomic write (temp file + rename) so a crash never leaves half a file.
    pub fn save(&self) -> Result<(), String> {
        let tmp = self.path.with_extension("tmp");
        let json = serde_json::to_vec_pretty(&self.state).map_err(|e| e.to_string())?;
        std::fs::write(&tmp, json).map_err(|e| format!("cannot write {}: {e}", tmp.display()))?;
        std::fs::rename(&tmp, &self.path)
            .map_err(|e| format!("cannot replace {}: {e}", self.path.display()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_and_missing_file() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("s.json");
        let (mut s, w) = RestoreStore::open(&p);
        assert!(w.is_none() && s.state.interfaces.is_empty());
        s.state.interfaces.insert(
            "if1".into(),
            IfaceOriginal {
                original_v4: "8.8.8.8".into(),
                original_v6: None,
                orphaned: false,
            },
        );
        s.state
            .policies
            .insert("k\\v".into(), Some(PolicyValue::Dword(1)));
        s.save().unwrap();
        let (s2, w2) = RestoreStore::open(&p);
        assert!(w2.is_none());
        assert_eq!(s2.state, s.state);
    }

    #[test]
    fn corrupt_file_is_kept_aside_not_deleted() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("s.json");
        std::fs::write(&p, "{ not json").unwrap();
        let (s, w) = RestoreStore::open(&p);
        assert!(w.unwrap().contains("unreadable"));
        assert!(s.state.interfaces.is_empty());
        assert!(dir.path().join("s.corrupt").exists());
    }
}
