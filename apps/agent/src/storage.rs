//! SQLite persistence. The schema lives in `packages/database/migrations/*.sql`
//! (single source of truth, also verified against the TypeScript package).

use crate::domain::{validate_rule_domain, DomainRuleEntry};
use rusqlite::{params, Connection};
use std::path::Path;

/// Append-only. Never edit a released migration; add a new one.
const MIGRATIONS: &[(i64, &str, &str)] = &[(
    1,
    "initial schema",
    include_str!("../../../packages/database/migrations/0001_initial.sql"),
)];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ListKind {
    CustomBlocklist,
    Allowlist,
}

impl ListKind {
    /// Table names come from this fixed mapping, never from user input.
    fn table(self) -> &'static str {
        match self {
            ListKind::CustomBlocklist => "custom_blocklist",
            ListKind::Allowlist => "allowlist",
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum StorageError {
    #[error("invalid domain: {0}")]
    InvalidDomain(String),
    #[error("database schema v{found} is newer than this build supports (v{supported})")]
    SchemaTooNew { found: i64, supported: i64 },
    #[error(transparent)]
    Sql(#[from] rusqlite::Error),
}

pub struct Database {
    conn: Connection,
}

impl Database {
    /// Opens (creating if needed) the database and applies pending migrations.
    pub fn open(path: &Path) -> Result<Self, StorageError> {
        let conn = Connection::open(path)?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        Self::init(conn)
    }

    pub fn open_in_memory() -> Result<Self, StorageError> {
        Self::init(Connection::open_in_memory()?)
    }

    fn init(conn: Connection) -> Result<Self, StorageError> {
        conn.pragma_update(None, "foreign_keys", "ON")?;
        let mut db = Self { conn };
        db.migrate()?;
        Ok(db)
    }

    pub fn schema_version(&self) -> Result<i64, StorageError> {
        Ok(self.conn.query_row(
            "SELECT COALESCE(MAX(version), 0) FROM schema_migrations",
            [],
            |r| r.get(0),
        )?)
    }

    fn migrate(&mut self) -> Result<(), StorageError> {
        self.conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS schema_migrations (version INTEGER PRIMARY KEY, name TEXT NOT NULL, applied_at TEXT NOT NULL) STRICT;",
        )?;
        let current = self.schema_version()?;
        let latest = MIGRATIONS.last().map_or(0, |m| m.0);
        if current > latest {
            return Err(StorageError::SchemaTooNew {
                found: current,
                supported: latest,
            });
        }
        for (version, name, sql) in MIGRATIONS.iter().filter(|m| m.0 > current) {
            let tx = self.conn.transaction()?;
            tx.execute_batch(sql)?;
            tx.execute(
                "INSERT INTO schema_migrations (version, name, applied_at) VALUES (?1, ?2, strftime('%Y-%m-%dT%H:%M:%fZ','now'))",
                params![version, name],
            )?;
            tx.commit()?;
        }
        Ok(())
    }

    /// Validates + normalizes the domain, then stores it (upsert).
    pub fn add_domain(
        &self,
        list: ListKind,
        domain: &str,
        include_subdomains: bool,
    ) -> Result<DomainRuleEntry, StorageError> {
        let v = validate_rule_domain(domain, include_subdomains)
            .map_err(StorageError::InvalidDomain)?;
        let sql = format!(
            "INSERT INTO {} (domain, include_subdomains, created_at) VALUES (?1, ?2, strftime('%Y-%m-%dT%H:%M:%fZ','now')) \
             ON CONFLICT(domain) DO UPDATE SET include_subdomains = excluded.include_subdomains",
            list.table()
        );
        self.conn
            .execute(&sql, params![v.domain, i64::from(v.include_subdomains)])?;
        Ok(DomainRuleEntry {
            domain: v.domain,
            include_subdomains: v.include_subdomains,
            category: None,
        })
    }

    pub fn remove_domain(&self, list: ListKind, domain: &str) -> Result<bool, StorageError> {
        let Ok(v) = validate_rule_domain(domain, true) else {
            return Ok(false);
        };
        let sql = format!("DELETE FROM {} WHERE domain = ?1", list.table());
        Ok(self.conn.execute(&sql, params![v.domain])? > 0)
    }

    pub fn list_domains(&self, list: ListKind) -> Result<Vec<DomainRuleEntry>, StorageError> {
        let sql = format!(
            "SELECT domain, include_subdomains FROM {} ORDER BY domain",
            list.table()
        );
        let mut stmt = self.conn.prepare(&sql)?;
        let rows = stmt.query_map([], |r| {
            Ok(DomainRuleEntry {
                domain: r.get(0)?,
                include_subdomains: r.get::<_, i64>(1)? == 1,
                category: None,
            })
        })?;
        Ok(rows.collect::<Result<Vec<_>, _>>()?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn migrates_and_reopens_idempotently() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("t.sqlite");
        let db = Database::open(&path).unwrap();
        assert_eq!(db.schema_version().unwrap(), 1);
        db.add_domain(ListKind::CustomBlocklist, "Example.com.", true)
            .unwrap();
        drop(db);
        let db = Database::open(&path).unwrap();
        assert_eq!(db.schema_version().unwrap(), 1);
        let l = db.list_domains(ListKind::CustomBlocklist).unwrap();
        assert_eq!(l.len(), 1);
        assert_eq!(l[0].domain, "example.com");
    }

    #[test]
    fn rejects_newer_schema() {
        let db = Database::open_in_memory().unwrap();
        db.conn
            .execute(
                "INSERT INTO schema_migrations VALUES (99, 'future', 'x')",
                [],
            )
            .unwrap();
        let mut db = db;
        assert!(matches!(
            db.migrate(),
            Err(StorageError::SchemaTooNew { found: 99, .. })
        ));
    }

    #[test]
    fn validates_normalizes_and_upserts() {
        let db = Database::open_in_memory().unwrap();
        let e = db
            .add_domain(ListKind::Allowlist, "HTTPS://WWW.Example.com/x", false)
            .unwrap();
        assert_eq!(
            (e.domain.as_str(), e.include_subdomains),
            ("www.example.com", false)
        );
        assert!(db.add_domain(ListKind::Allowlist, "com", true).is_err());
        assert!(db
            .add_domain(ListKind::Allowlist, "not a domain", true)
            .is_err());
        db.add_domain(ListKind::CustomBlocklist, "a.com", false)
            .unwrap();
        db.add_domain(ListKind::CustomBlocklist, "A.COM", true)
            .unwrap();
        let l = db.list_domains(ListKind::CustomBlocklist).unwrap();
        assert_eq!(l.len(), 1);
        assert!(l[0].include_subdomains);
        assert!(db
            .remove_domain(ListKind::CustomBlocklist, "a.com.")
            .unwrap());
        assert!(!db
            .remove_domain(ListKind::CustomBlocklist, "a.com")
            .unwrap());
        assert!(!db
            .remove_domain(ListKind::CustomBlocklist, "garbage input")
            .unwrap());
    }

    #[test]
    fn lists_are_separate_and_blocked_only_constraint_holds() {
        let db = Database::open_in_memory().unwrap();
        db.add_domain(ListKind::Allowlist, "a.com", true).unwrap();
        assert!(db
            .list_domains(ListKind::CustomBlocklist)
            .unwrap()
            .is_empty());
        let bad_action = db.conn.execute(
            "INSERT INTO access_attempts (timestamp, hostname, matched_rule, rule_type, action) VALUES ('t','h','r','global_blocklist','ALLOW')",
            [],
        );
        assert!(bad_action.is_err());
    }
}
