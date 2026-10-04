import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { MIGRATIONS, SavingGraceDatabase } from '@savinggrace/database';

describe('SavingGraceDatabase', () => {
  it('applies migrations on open and is idempotent across reopen', () => {
    const path = join(mkdtempSync(join(tmpdir(), 'sg-db-')), 'sg.sqlite');
    const a = SavingGraceDatabase.open(path);
    expect(a.schemaVersion).toBe(MIGRATIONS.length);
    a.addDomain('custom_blocklist', 'Example.com.');
    a.close();
    const b = SavingGraceDatabase.open(path);
    expect(b.schemaVersion).toBe(MIGRATIONS.length);
    expect(b.listDomains('custom_blocklist')).toEqual([{ domain: 'example.com', includeSubdomains: true }]);
    b.close();
  });

  it('stores normalized domains and rejects invalid ones', () => {
    const db = SavingGraceDatabase.open(':memory:');
    expect(db.addDomain('allowlist', 'HTTPS://WWW.Example.com/x', false)).toEqual({ domain: 'www.example.com', includeSubdomains: false });
    expect(() => db.addDomain('allowlist', 'com')).toThrow();
    expect(() => db.addDomain('allowlist', 'not a domain')).toThrow();
    expect(() => db.addDomain('users; DROP TABLE x' as never, 'a.com')).toThrow(/Unknown list/);
  });

  it('adding a duplicate updates instead of failing; remove reports result', () => {
    const db = SavingGraceDatabase.open(':memory:');
    db.addDomain('custom_blocklist', 'a.com', false);
    db.addDomain('custom_blocklist', 'A.COM', true);
    expect(db.listDomains('custom_blocklist')).toEqual([{ domain: 'a.com', includeSubdomains: true }]);
    expect(db.removeDomain('custom_blocklist', 'a.com.')).toBe(true);
    expect(db.removeDomain('custom_blocklist', 'a.com')).toBe(false);
    expect(db.removeDomain('custom_blocklist', 'garbage input')).toBe(false);
  });

  it('keeps allowlist and custom blocklist separate', () => {
    const db = SavingGraceDatabase.open(':memory:');
    db.addDomain('allowlist', 'a.com');
    expect(db.listDomains('custom_blocklist')).toEqual([]);
  });

  it('settings round-trip', () => {
    const db = SavingGraceDatabase.open(':memory:');
    expect(db.getSetting('k')).toBeNull();
    db.setSetting('k', 'v1');
    db.setSetting('k', 'v2');
    expect(db.getSetting('k')).toBe('v2');
  });

  it('stores blocked attempts only and counts by time', () => {
    const db = SavingGraceDatabase.open(':memory:');
    const base = { hostname: 'x.com', matchedRule: 'x.com', ruleType: 'global_blocklist', action: 'BLOCK', process: 'firefox.exe', category: 'adult' } as const;
    db.insertAttempt({ ...base, timestamp: '2026-10-04T05:00:00.000Z' });
    db.insertAttempt({ ...base, timestamp: '2026-10-04T06:00:00.000Z' });
    expect(db.countAttemptsSince('2026-10-04T05:30:00.000Z')).toBe(1);
    expect(() => db.insertAttempt({ ...base, action: 'ALLOW' as never, timestamp: '2026-10-04T07:00:00.000Z' })).toThrow();
    expect(() => db.insertAttempt({ ...base, ruleType: 'allowlist' as never, timestamp: '2026-10-04T07:00:00.000Z' })).toThrow();
  });
});
