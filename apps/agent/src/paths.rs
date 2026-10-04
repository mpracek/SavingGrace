//! On-disk layout of the agent's data directory.

use std::path::PathBuf;

#[derive(Debug, Clone)]
pub struct DataDirs {
    pub root: PathBuf,
    pub config_file: PathBuf,
    pub database_file: PathBuf,
    pub global_list_file: PathBuf,
    pub logs_dir: PathBuf,
}

impl DataDirs {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        let root: PathBuf = root.into();
        Self {
            config_file: root.join("config.json"),
            database_file: root.join("savinggrace.sqlite"),
            global_list_file: root.join("rules").join("adult-domains.json"),
            logs_dir: root.join("logs"),
            root,
        }
    }

    /// `%ProgramData%\SavingGrace` on Windows. Other platforms have no default:
    /// the data directory must be given explicitly (development/testing only).
    pub fn platform_default() -> Option<Self> {
        #[cfg(windows)]
        {
            std::env::var_os("PROGRAMDATA").map(|p| Self::new(PathBuf::from(p).join("SavingGrace")))
        }
        #[cfg(not(windows))]
        {
            None
        }
    }

    pub fn ensure_created(&self) -> std::io::Result<()> {
        std::fs::create_dir_all(&self.logs_dir)?;
        if let Some(parent) = self.global_list_file.parent() {
            std::fs::create_dir_all(parent)?;
        }
        Ok(())
    }
}
