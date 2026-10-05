import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { ConfigError, DEFAULT_CONFIG, loadConfigFile, parseConfig } from '@savinggrace/configuration';

describe('parseConfig', () => {
  it('defaults match the specification', () => {
    expect(DEFAULT_CONFIG.temporaryDisableEnabled).toBe(true);
    expect(DEFAULT_CONFIG.disableChallengeWordCount).toBe(50);
    expect(DEFAULT_CONFIG.disableDurationsMinutes).toEqual([5, 15, 30, 60]);
    expect(DEFAULT_CONFIG.uiLanguage).toBe('sl');
  });
  it('merges partial config over defaults', () => {
    const c = parseConfig({ disableChallengeWordCount: 75, temporaryDisableEnabled: false });
    expect(c.disableChallengeWordCount).toBe(75);
    expect(c.temporaryDisableEnabled).toBe(false);
    expect(c.attemptRetentionDays).toBe(90);
  });
  it('accepts loopback listeners and upstreams with optional port', () => {
    const c = parseConfig({ dnsListen: ['127.0.0.1:5353', '[::1]:5353'], dnsUpstreams: ['9.9.9.9', '[2620:fe::fe]:53'], enforceSystemProtection: false });
    expect(c.dnsListen).toEqual(['127.0.0.1:5353', '[::1]:5353']);
    expect(c.enforceSystemProtection).toBe(false);
  });
  it('accepts English UI language', () => {
    expect(parseConfig({ uiLanguage: 'en' }).uiLanguage).toBe('en');
  });
  it('normalizes durations (unique, sorted)', () => {
    expect(parseConfig({ disableDurationsMinutes: [30, 5, 5] }).disableDurationsMinutes).toEqual([5, 30]);
  });
  it.each([
    [{ disableChallengeWordCount: 9 }],
    [{ disableChallengeWordCount: 101 }],
    [{ disableChallengeWordCount: 50.5 }],
    [{ disableChallengeWordCount: '50' }],
    [{ temporaryDisableEnabled: 'yes' }],
    [{ disableDurationsMinutes: [] }],
    [{ disableDurationsMinutes: [0] }],
    [{ disableDurationsMinutes: [100000] }],
    [{ onInvalidInput: 'maybe' }],
    [{ uiLanguage: 'de' }],
    [{ dnsListen: [] }],
    [{ dnsListen: ['0.0.0.0:53'] }],
    [{ dnsListen: ['192.168.1.5:53'] }],
    [{ dnsListen: ['localhost'] }],
    [{ dnsUpstreams: ['127.0.0.1'] }],
    [{ dnsUpstreams: ['not-an-ip'] }],
    [{ dnsUpstreams: ['0.0.0.0'] }],
    [{ dnsEnabled: 'yes' }],
    [{ unknownKey: 1 }],
    [[]],
    [null],
  ])('rejects invalid config %#', (raw) => {
    expect(() => parseConfig(raw)).toThrow(ConfigError);
  });
  it('does not mutate DEFAULT_CONFIG', () => {
    parseConfig({ disableChallengeWordCount: 10 });
    expect(DEFAULT_CONFIG.disableChallengeWordCount).toBe(50);
  });
});

describe('loadConfigFile', () => {
  const dir = mkdtempSync(join(tmpdir(), 'sg-cfg-'));
  it('missing file yields defaults', () => {
    expect(loadConfigFile(join(dir, 'nope.json'))).toEqual(DEFAULT_CONFIG);
  });
  it('invalid JSON throws ConfigError', () => {
    const p = join(dir, 'bad.json');
    writeFileSync(p, '{ not json');
    expect(() => loadConfigFile(p)).toThrow(ConfigError);
  });
  it('valid file is parsed', () => {
    const p = join(dir, 'ok.json');
    writeFileSync(p, JSON.stringify({ disableChallengeWordCount: 25 }));
    expect(loadConfigFile(p).disableChallengeWordCount).toBe(25);
  });
});
