export interface Migration {
  readonly version: number;
  readonly name: string;
  readonly sql: string;
}

/**
 * Append-only. Never edit a released migration; add a new one.
 * The SQL is deliberately plain SQLite so a native (Rust/C#) agent can reuse it.
 */
export const MIGRATIONS: readonly Migration[] = [
  {
    version: 1,
    name: 'initial schema',
    sql: `
CREATE TABLE settings (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
) STRICT;

CREATE TABLE custom_blocklist (
  domain TEXT PRIMARY KEY,
  include_subdomains INTEGER NOT NULL CHECK (include_subdomains IN (0, 1)),
  created_at TEXT NOT NULL
) STRICT;

CREATE TABLE allowlist (
  domain TEXT PRIMARY KEY,
  include_subdomains INTEGER NOT NULL CHECK (include_subdomains IN (0, 1)),
  created_at TEXT NOT NULL
) STRICT;

CREATE TABLE access_attempts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  timestamp TEXT NOT NULL,
  hostname TEXT NOT NULL,
  matched_rule TEXT NOT NULL,
  rule_type TEXT NOT NULL CHECK (rule_type IN ('custom_blocklist', 'global_blocklist', 'classifier')),
  action TEXT NOT NULL CHECK (action = 'BLOCK'),
  process TEXT,
  category TEXT
) STRICT;
CREATE INDEX idx_access_attempts_timestamp ON access_attempts (timestamp);

CREATE TABLE disable_audit (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  disabled_at TEXT NOT NULL,
  duration_minutes INTEGER NOT NULL CHECK (duration_minutes > 0),
  scheduled_reenable_at TEXT NOT NULL,
  reenabled_at TEXT,
  reenable_reason TEXT
) STRICT;
`,
  },
];
