import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { matchesDomain, normalizeHostname, validateRuleDomain } from '@savinggrace/domain-matcher';
import { RuleEngine } from '@savinggrace/rule-engine';
import { MIGRATIONS } from '@savinggrace/database';

const root = new URL('../../', import.meta.url);
const vectors = JSON.parse(readFileSync(new URL('tests/conformance/domain-vectors.json', root), 'utf8'));

describe('conformance vectors (shared with the Rust agent)', () => {
  it.each(vectors.normalize as [string, string | null][])('normalize %j', (input, expected) => {
    expect(normalizeHostname(input)).toBe(expected);
  });
  it.each(vectors.match as [string, string, boolean, boolean][])('match %s vs %s (sub=%s)', (h, r, sub, expected) => {
    expect(matchesDomain(h, r, sub)).toBe(expected);
  });
  it.each(vectors.validateRule as [string, [string, boolean] | null][])('validateRule %j', (input, expected) => {
    const v = validateRuleDomain(input);
    if (expected === null) expect(v.ok).toBe(false);
    else expect(v).toEqual({ ok: true, domain: expected[0], includeSubdomains: expected[1] });
  });
  it.each(vectors.engine as { name: string; allow: unknown[]; custom: unknown[]; global: unknown[]; target: string; action: string; ruleType: string }[])(
    'engine: $name',
    (c) => {
      const e = new RuleEngine({ allowlist: c.allow as never, customBlocklist: c.custom as never, globalBlocklist: c.global as never });
      expect(e.evaluate({ target: c.target })).toMatchObject({ action: c.action, ruleType: c.ruleType });
    },
  );
});

describe('SQL schema single source of truth', () => {
  it('TypeScript migration 1 equals packages/database/migrations/0001_initial.sql', () => {
    const sql = readFileSync(new URL('packages/database/migrations/0001_initial.sql', root), 'utf8');
    expect(MIGRATIONS[0]?.sql.trim()).toBe(sql.trim());
  });
});
