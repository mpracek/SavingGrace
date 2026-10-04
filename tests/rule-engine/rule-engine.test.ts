import { describe, expect, it } from 'vitest';
import { RULE_PRIORITY, RuleEngine, parseGlobalList, GlobalListError, type Classifier } from '@savinggrace/rule-engine';

const engine = (o: ConstructorParameters<typeof RuleEngine>[0] = {}) => new RuleEngine(o);

describe('rule priority', () => {
  it('is documented as allowlist > custom > global > classifier > default', () => {
    expect([...RULE_PRIORITY]).toEqual(['allowlist', 'custom_blocklist', 'global_blocklist', 'classifier', 'default']);
  });

  it('allowlist beats custom blocklist and global blocklist', () => {
    const e = engine({ allowlist: ['example.com'], customBlocklist: ['example.com'], globalBlocklist: ['example.com'] });
    expect(e.evaluate({ target: 'example.com' })).toMatchObject({ action: 'ALLOW', ruleType: 'allowlist' });
  });
  it('custom blocklist beats global blocklist', () => {
    const e = engine({ customBlocklist: [{ domain: 'example.com', includeSubdomains: true, category: 'custom' }], globalBlocklist: [{ domain: 'example.com', includeSubdomains: true, category: 'adult' }] });
    expect(e.evaluate({ target: 'example.com' })).toMatchObject({ action: 'BLOCK', ruleType: 'custom_blocklist', category: 'custom' });
  });
  it('global blocklist blocks and reports category', () => {
    const e = engine({ globalBlocklist: [{ domain: 'bad.example', includeSubdomains: true, category: 'adult' }] });
    expect(e.evaluate({ target: 'https://www.bad.example/x' })).toEqual({
      action: 'BLOCK', ruleType: 'global_blocklist', matchedRule: 'bad.example', hostname: 'www.bad.example', category: 'adult', warnings: [],
    });
  });
  it('unmatched hosts are allowed by default', () => {
    expect(engine().evaluate({ target: 'good.example' })).toMatchObject({ action: 'ALLOW', ruleType: 'default', matchedRule: null });
  });
});

describe('allowlist scoping', () => {
  it('allowing a subdomain does not unblock the parent or siblings', () => {
    const e = engine({ allowlist: [{ domain: 'safe.bad.example', includeSubdomains: false }], globalBlocklist: ['bad.example'] });
    expect(e.evaluate({ target: 'safe.bad.example' }).action).toBe('ALLOW');
    expect(e.evaluate({ target: 'bad.example' }).action).toBe('BLOCK');
    expect(e.evaluate({ target: 'other.bad.example' }).action).toBe('BLOCK');
    expect(e.evaluate({ target: 'x.safe.bad.example' }).action).toBe('BLOCK');
  });
});

describe('hostname edge cases flow through the engine', () => {
  const e = engine({ globalBlocklist: ['example.com'] });
  it.each(['EXAMPLE.COM', 'example.com.', 'www.example.com:8443', 'https://a.b.example.com/p?q', 'EXAMPLE.com.:80'])('blocks %s', (t) => {
    expect(e.evaluate({ target: t }).action).toBe('BLOCK');
  });
  it.each(['example.com.evil.com', 'evil-example.com', 'notexample.com'])('allows %s', (t) => {
    expect(e.evaluate({ target: t }).action).toBe('ALLOW');
  });
});

describe('invalid input policy', () => {
  it('allows by default and records ruleType invalid_input', () => {
    expect(engine().evaluate({ target: 'not a host' })).toMatchObject({ action: 'ALLOW', ruleType: 'invalid_input', hostname: null });
  });
  it('blocks when configured', () => {
    expect(engine({ onInvalidInput: 'block' }).evaluate({ target: '' })).toMatchObject({ action: 'BLOCK', ruleType: 'invalid_input' });
  });
});

describe('classifiers (extension point)', () => {
  const blocker: Classifier = { id: 'test-url', classify: () => ({ block: true, category: 'adult', confidence: 0.9, reason: 't' }) };
  const thrower: Classifier = { id: 'broken', classify: () => { throw new Error('boom'); } };

  it('sync evaluate ignores classifiers', () => {
    expect(engine({ classifiers: [blocker] }).evaluate({ target: 'x.example' }).action).toBe('ALLOW');
  });
  it('evaluateAsync blocks via classifier on unmatched hosts', async () => {
    const d = await engine({ classifiers: [blocker] }).evaluateAsync({ target: 'x.example' });
    expect(d).toMatchObject({ action: 'BLOCK', ruleType: 'classifier', matchedRule: 'test-url', category: 'adult' });
  });
  it('allowlist wins over a blocking classifier', async () => {
    const d = await engine({ allowlist: ['x.example'], classifiers: [blocker] }).evaluateAsync({ target: 'x.example' });
    expect(d).toMatchObject({ action: 'ALLOW', ruleType: 'allowlist' });
  });
  it('a throwing classifier is reported as a warning and does not stop later classifiers', async () => {
    const d = await engine({ classifiers: [thrower, blocker] }).evaluateAsync({ target: 'x.example' });
    expect(d.action).toBe('BLOCK');
    const d2 = await engine({ classifiers: [thrower] }).evaluateAsync({ target: 'x.example' });
    expect(d2.action).toBe('ALLOW');
    expect(d2.warnings[0]).toContain('broken');
  });
});

describe('parseGlobalList', () => {
  it('accepts v1 (strings) and v2 (objects)', () => {
    expect(parseGlobalList({ version: 1, updated: '2026-01-01', domains: ['A.com'] }).entries).toEqual([{ domain: 'a.com', includeSubdomains: true, category: 'adult' }]);
    expect(parseGlobalList({ version: 2, updated: '2026-01-01', domains: [{ domain: 'b.com', category: 'x' }] }).entries[0]?.category).toBe('x');
  });
  it.each([
    [{ version: 3, updated: '2026-01-01', domains: [] }],
    [{ version: 1, updated: 'yesterday', domains: [] }],
    [{ version: 1, updated: '2026-01-01', domains: ['com'] }],
    [{ version: 1, updated: '2026-01-01', domains: [42] }],
    [{ version: 2, updated: '2026-01-01', domains: ['a.com'] }],
    [null],
  ])('rejects invalid list %#', (raw) => {
    expect(() => parseGlobalList(raw)).toThrow(GlobalListError);
  });
});
