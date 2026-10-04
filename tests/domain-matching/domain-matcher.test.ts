import { describe, expect, it } from 'vitest';
import { DomainSet, matchesDomain, normalizeHostname, validateRuleDomain } from '@savinggrace/domain-matcher';

describe('matchesDomain: label boundaries', () => {
  it.each(['example.com', 'www.example.com', 'sub.example.com', 'a.b.example.com'])('matches %s', (h) => {
    expect(matchesDomain(h, 'example.com')).toBe(true);
  });
  it.each(['example.com.evil.com', 'evil-example.com', 'notexample.com', 'example.co', 'com', 'xexample.com'])(
    'does not match %s',
    (h) => {
      expect(matchesDomain(h, 'example.com')).toBe(false);
    },
  );
  it('without includeSubdomains only the exact host matches', () => {
    expect(matchesDomain('example.com', 'example.com', false)).toBe(true);
    expect(matchesDomain('www.example.com', 'example.com', false)).toBe(false);
  });
});

describe('normalizeHostname', () => {
  it.each([
    ['EXAMPLE.COM', 'example.com'],
    ['Example.Com.', 'example.com'],
    ['example.com:8080', 'example.com'],
    ['https://www.Example.com:443/path?q=1#frag', 'www.example.com'],
    ['http://user:pass@example.com/', 'example.com'],
    ['//example.com/x', 'example.com'],
    ['  example.com  ', 'example.com'],
    ['http://example.com\\@evil.com/', 'example.com'],
    ['http://evil.com\\@example.com/', 'evil.com'],
    ['bücher.example', 'xn--bcher-kva.example'],
    ['xn--bcher-kva.example', 'xn--bcher-kva.example'],
    ['http://[::1]:8080/', '[::1]'],
    ['http://127.0.0.1:80/', '127.0.0.1'],
    ['http://0x7f.1/', '127.0.0.1'],
  ])('%s -> %s', (input, expected) => {
    expect(normalizeHostname(input)).toBe(expected);
  });

  it.each([
    '', '   ', '.', '..', 'example.com..', '.example.com', 'exa mple.com', 'exa\tmple.com', 'a..b.com',
    'http://', 'javascript:alert(1)', 'file:///etc/passwd', 'http://exa%20mple.com', 'exam!ple.com',
    `${'a'.repeat(64)}.com`, `${'a.'.repeat(130)}com`, 'http://[::1', 'x'.repeat(3000),
  ])('rejects malformed input %j', (input) => {
    expect(normalizeHostname(input)).toBeNull();
  });

  it('never throws on non-string input', () => {
    expect(normalizeHostname(undefined as unknown as string)).toBeNull();
    expect(normalizeHostname(42 as unknown as string)).toBeNull();
  });
});

describe('IDN / punycode equivalence', () => {
  it('unicode and punycode forms match each other', () => {
    expect(matchesDomain('www.bücher.example', 'xn--bcher-kva.example')).toBe(true);
    expect(matchesDomain('www.xn--bcher-kva.example', 'bücher.example')).toBe(true);
  });
  it('uppercase unicode matches', () => {
    expect(matchesDomain('BÜCHER.EXAMPLE', 'bücher.example')).toBe(true);
  });
});

describe('IP literals', () => {
  it('match exactly and never by suffix', () => {
    expect(matchesDomain('1.2.3.4', '1.2.3.4')).toBe(true);
    expect(matchesDomain('11.2.3.4', '1.2.3.4')).toBe(false);
    expect(matchesDomain('0.1.2.3.4', '1.2.3.4')).toBe(false);
  });
});

describe('validateRuleDomain', () => {
  it('accepts domains and extracts hosts from URLs', () => {
    expect(validateRuleDomain('HTTPS://WWW.Example.com/a')).toEqual({ ok: true, domain: 'www.example.com', includeSubdomains: true });
  });
  it('rejects single-label rules (would cover a whole TLD)', () => {
    expect(validateRuleDomain('com').ok).toBe(false);
    expect(validateRuleDomain('localhost').ok).toBe(false);
  });
  it('forces IP rules to exact-match', () => {
    expect(validateRuleDomain('10.0.0.1', true)).toEqual({ ok: true, domain: '10.0.0.1', includeSubdomains: false });
  });
  it('rejects garbage', () => {
    expect(validateRuleDomain('not a domain').ok).toBe(false);
  });
});

describe('DomainSet', () => {
  it('returns the most specific rule', () => {
    const s = new DomainSet(['example.com', { domain: 'a.example.com', includeSubdomains: true, category: 'x' }]);
    expect(s.match('z.a.example.com')?.domain).toBe('a.example.com');
    expect(s.match('b.example.com')?.domain).toBe('example.com');
  });
  it('exact-only entries do not cover subdomains', () => {
    const s = new DomainSet([{ domain: 'example.com', includeSubdomains: false }]);
    expect(s.match('example.com')).not.toBeNull();
    expect(s.match('www.example.com')).toBeNull();
  });
  it('a more specific exact-only rule does not hide a broader subdomain rule', () => {
    const s = new DomainSet(['example.com', { domain: 'www.example.com', includeSubdomains: false }]);
    expect(s.match('x.www.example.com')?.domain).toBe('example.com');
  });
  it('does not match look-alikes', () => {
    const s = new DomainSet(['example.com']);
    for (const h of ['example.com.evil.com', 'evil-example.com', 'notexample.com']) expect(s.match(h)).toBeNull();
  });
  it('merges duplicates (subdomain coverage wins) and supports removal', () => {
    const s = new DomainSet([{ domain: 'Example.com.', includeSubdomains: false }, 'example.com']);
    expect(s.size).toBe(1);
    expect(s.match('www.example.com')).not.toBeNull();
    expect(s.remove('EXAMPLE.COM')).toBe(true);
    expect(s.size).toBe(0);
  });
  it('throws on invalid rule domains', () => {
    expect(() => new DomainSet(['com'])).toThrow();
  });
});
