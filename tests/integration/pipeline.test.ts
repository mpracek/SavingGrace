import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { loadConfigFile } from '@savinggrace/configuration';
import { SavingGraceDatabase } from '@savinggrace/database';
import { RuleEngine, loadGlobalListFile } from '@savinggrace/rule-engine';

const listPath = fileURLToPath(new URL('../../data/adult-domains/domains.json', import.meta.url));

describe('config + shipped global list + database + rule engine', () => {
  it('the shipped global list is valid and non-empty', () => {
    const list = loadGlobalListFile(listPath);
    expect(list.entries.length).toBeGreaterThan(0);
    expect(new Set(list.entries.map((e) => e.domain)).size).toBe(list.entries.length);
  });

  it('end-to-end: user lists from SQLite override the global list; blocked attempts persist', () => {
    const cfg = loadConfigFile('/nonexistent/savinggrace.json');
    const db = SavingGraceDatabase.open(':memory:');
    const global = loadGlobalListFile(listPath);
    const blocked = global.entries[0]!.domain;

    db.addDomain('custom_blocklist', 'my-extra-block.example');
    const buildEngine = () =>
      new RuleEngine({
        allowlist: db.listDomains('allowlist'),
        customBlocklist: db.listDomains('custom_blocklist'),
        globalBlocklist: global.entries,
        onInvalidInput: cfg.onInvalidInput,
      });

    let engine = buildEngine();
    const d1 = engine.evaluate({ target: `www.${blocked}`, process: 'firefox.exe' });
    expect(d1).toMatchObject({ action: 'BLOCK', ruleType: 'global_blocklist', matchedRule: blocked });
    expect(engine.evaluate({ target: 'sub.my-extra-block.example' }).ruleType).toBe('custom_blocklist');

    if (d1.action === 'BLOCK' && d1.ruleType !== 'default' && d1.ruleType !== 'invalid_input' && d1.ruleType !== 'allowlist') {
      db.insertAttempt({ timestamp: new Date().toISOString(), hostname: d1.hostname!, matchedRule: d1.matchedRule!, ruleType: d1.ruleType, action: 'BLOCK', process: 'firefox.exe', category: d1.category });
    }
    expect(db.countAttemptsSince('1970-01-01T00:00:00.000Z')).toBe(1);

    db.addDomain('allowlist', blocked);
    engine = buildEngine();
    expect(engine.evaluate({ target: blocked })).toMatchObject({ action: 'ALLOW', ruleType: 'allowlist' });
  });
});
