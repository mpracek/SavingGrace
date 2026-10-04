import { DatabaseSync } from 'node:sqlite';
import { validateRuleDomain } from '@savinggrace/domain-matcher';
import type { AccessAttempt, DomainRuleEntry } from '@savinggrace/shared-types';
import { MIGRATIONS } from './migrations.js';

export { MIGRATIONS } from './migrations.js';

export type ListName = 'custom_blocklist' | 'allowlist';
const LIST_TABLES: readonly ListName[] = ['custom_blocklist', 'allowlist'];

export type NewAccessAttempt = Omit<AccessAttempt, 'id'>;

export class SavingGraceDatabase {
  private constructor(private readonly db: DatabaseSync) {}

  /** Opens (creating if needed) the database and applies pending migrations. Use ":memory:" for tests. */
  static open(path: string): SavingGraceDatabase {
    const db = new DatabaseSync(path);
    db.exec('PRAGMA foreign_keys = ON;');
    if (path !== ':memory:') db.exec('PRAGMA journal_mode = WAL;');
    const instance = new SavingGraceDatabase(db);
    instance.migrate();
    return instance;
  }

  close(): void {
    this.db.close();
  }

  get schemaVersion(): number {
    const row = this.db.prepare('SELECT MAX(version) AS v FROM schema_migrations').get() as { v: number | null };
    return row.v ?? 0;
  }

  private migrate(): void {
    this.db.exec(
      'CREATE TABLE IF NOT EXISTS schema_migrations (version INTEGER PRIMARY KEY, name TEXT NOT NULL, applied_at TEXT NOT NULL) STRICT;',
    );
    const current = this.schemaVersion;
    const latest = MIGRATIONS[MIGRATIONS.length - 1]?.version ?? 0;
    if (current > latest) {
      throw new Error(`Database schema v${current} is newer than this build supports (v${latest}).`);
    }
    for (const m of MIGRATIONS.filter((x) => x.version > current)) {
      this.db.exec('BEGIN');
      try {
        this.db.exec(m.sql);
        this.db
          .prepare('INSERT INTO schema_migrations (version, name, applied_at) VALUES (?, ?, ?)')
          .run(m.version, m.name, new Date().toISOString());
        this.db.exec('COMMIT');
      } catch (err) {
        this.db.exec('ROLLBACK');
        throw err;
      }
    }
  }

  // ---- settings -----------------------------------------------------------
  getSetting(key: string): string | null {
    const row = this.db.prepare('SELECT value FROM settings WHERE key = ?').get(key) as { value: string } | undefined;
    return row?.value ?? null;
  }

  setSetting(key: string, value: string): void {
    this.db
      .prepare('INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value')
      .run(key, value);
  }

  // ---- allowlist / custom blocklist ---------------------------------------
  /** Validates + normalizes the domain, then stores it. Returns the stored entry. */
  addDomain(list: ListName, domain: string, includeSubdomains = true): DomainRuleEntry {
    this.assertList(list);
    const v = validateRuleDomain(domain, includeSubdomains);
    if (!v.ok) throw new Error(`Invalid domain "${domain}": ${v.reason}`);
    this.db
      .prepare(
        `INSERT INTO ${list} (domain, include_subdomains, created_at) VALUES (?, ?, ?)
         ON CONFLICT(domain) DO UPDATE SET include_subdomains = excluded.include_subdomains`,
      )
      .run(v.domain, v.includeSubdomains ? 1 : 0, new Date().toISOString());
    return { domain: v.domain, includeSubdomains: v.includeSubdomains };
  }

  removeDomain(list: ListName, domain: string): boolean {
    this.assertList(list);
    const v = validateRuleDomain(domain);
    if (!v.ok) return false;
    const res = this.db.prepare(`DELETE FROM ${list} WHERE domain = ?`).run(v.domain);
    return Number(res.changes) > 0;
  }

  listDomains(list: ListName): DomainRuleEntry[] {
    this.assertList(list);
    const rows = this.db
      .prepare(`SELECT domain, include_subdomains FROM ${list} ORDER BY domain`)
      .all() as { domain: string; include_subdomains: number }[];
    return rows.map((r) => ({ domain: r.domain, includeSubdomains: r.include_subdomains === 1 }));
  }

  // ---- access attempts (blocked only) -------------------------------------
  insertAttempt(a: NewAccessAttempt): number {
    const res = this.db
      .prepare(
        'INSERT INTO access_attempts (timestamp, hostname, matched_rule, rule_type, action, process, category) VALUES (?, ?, ?, ?, ?, ?, ?)',
      )
      .run(a.timestamp, a.hostname, a.matchedRule, a.ruleType, a.action, a.process, a.category);
    return Number(res.lastInsertRowid);
  }

  countAttemptsSince(isoTimestamp: string): number {
    const row = this.db
      .prepare('SELECT COUNT(*) AS n FROM access_attempts WHERE timestamp >= ?')
      .get(isoTimestamp) as { n: number };
    return row.n;
  }

  /** Table names come from a fixed whitelist, never from user input. */
  private assertList(list: string): asserts list is ListName {
    if (!LIST_TABLES.includes(list as ListName)) throw new Error(`Unknown list "${list}"`);
  }
}
