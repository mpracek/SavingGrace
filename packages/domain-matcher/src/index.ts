import type { DomainRuleEntry } from '@savinggrace/shared-types';

const ALLOWED_SCHEMES = new Set(['http:', 'https:', 'ws:', 'wss:', 'ftp:']);
const LABEL_RE = /^[a-z0-9_-]{1,63}$/;
const IPV4_RE = /^\d{1,3}(\.\d{1,3}){3}$/;
// eslint-disable-next-line no-control-regex
const FORBIDDEN_CHARS_RE = /[\u0000-\u0020\u007f]/;

/** True for IPv4 dotted-quad and bracketed IPv6 literals (as returned by normalizeHostname). */
export function isIpLiteral(host: string): boolean {
  return IPV4_RE.test(host) || (host.startsWith('[') && host.endsWith(']'));
}

/**
 * Turns a hostname, host:port or URL into a canonical hostname:
 * lowercase, punycode (IDN), single trailing dot removed, no port/userinfo/path.
 * Returns null when the input is not a valid hostname. Never throws.
 *
 * Parsing is delegated to the WHATWG URL parser so that we agree with browsers
 * on what the host of a URL is (e.g. backslashes, userinfo, numeric IPv4 forms).
 */
export function normalizeHostname(input: string): string | null {
  if (typeof input !== 'string') return null;
  let s = input.trim();
  if (s.length === 0 || s.length > 2048) return null;
  // URL parsing silently strips tabs/newlines; reject them instead.
  if (FORBIDDEN_CHARS_RE.test(s)) return null;

  if (!/^[a-z][a-z0-9+.-]*:\/\//i.test(s)) {
    s = s.startsWith('//') ? `http:${s}` : `http://${s}`;
  }

  let host: string;
  try {
    const url = new URL(s);
    if (!ALLOWED_SCHEMES.has(url.protocol)) return null;
    host = url.hostname;
  } catch {
    return null;
  }

  host = host.toLowerCase();
  if (host.startsWith('[')) {
    return host.endsWith(']') && host.length > 2 ? host : null;
  }
  if (host.endsWith('.')) host = host.slice(0, -1);
  if (host.length === 0 || host.length > 253) return null;
  for (const label of host.split('.')) {
    if (!LABEL_RE.test(label)) return null;
  }
  return host;
}

export type RuleDomainValidation =
  | { readonly ok: true; readonly domain: string; readonly includeSubdomains: boolean }
  | { readonly ok: false; readonly reason: string };

/**
 * Validates a domain a user wants to add to a list.
 * - Accepts a bare domain or a URL (the host is extracted).
 * - Rejects single-label names ("com", "localhost"): a rule must never cover a whole TLD.
 * - IP literals are accepted but are exact-match only.
 */
export function validateRuleDomain(input: string, includeSubdomains = true): RuleDomainValidation {
  const domain = normalizeHostname(input);
  if (domain === null) return { ok: false, reason: 'Not a valid hostname.' };
  if (isIpLiteral(domain)) return { ok: true, domain, includeSubdomains: false };
  if (!domain.includes('.')) {
    return { ok: false, reason: 'A rule needs at least two labels (e.g. example.com).' };
  }
  return { ok: true, domain, includeSubdomains };
}

/**
 * Label-boundary domain matching.
 * `ruleDomain` matches `host` if host equals it, or (when includeSubdomains)
 * host ends with "." + ruleDomain. Both sides are normalized first.
 * IP literals only ever match exactly.
 */
export function matchesDomain(host: string, ruleDomain: string, includeSubdomains = true): boolean {
  const h = normalizeHostname(host);
  const r = normalizeHostname(ruleDomain);
  if (h === null || r === null) return false;
  if (h === r) return true;
  if (!includeSubdomains || isIpLiteral(h) || isIpLiteral(r)) return false;
  return h.endsWith(`.${r}`);
}

/**
 * Set of domain rules with O(labels) lookup. Lookup walks the host's suffixes
 * from most to least specific, so a match is always on a label boundary.
 */
export class DomainSet {
  private readonly entries = new Map<string, DomainRuleEntry>();

  constructor(initial: Iterable<DomainRuleEntry | string> = []) {
    for (const item of initial) this.add(item);
  }

  get size(): number {
    return this.entries.size;
  }

  /** Adds a rule. Throws on an invalid domain. Duplicates merge (subdomain coverage wins). */
  add(item: DomainRuleEntry | string): void {
    const raw = typeof item === 'string' ? { domain: item, includeSubdomains: true } : item;
    const v = validateRuleDomain(raw.domain, raw.includeSubdomains);
    if (!v.ok) throw new Error(`Invalid rule domain "${raw.domain}": ${v.reason}`);
    const existing = this.entries.get(v.domain);
    const category = existing?.category ?? raw.category;
    const merged: DomainRuleEntry = {
      domain: v.domain,
      includeSubdomains: (existing?.includeSubdomains ?? false) || v.includeSubdomains,
      ...(category !== undefined ? { category } : {}),
    };
    this.entries.set(v.domain, merged);
  }

  remove(domain: string): boolean {
    const n = normalizeHostname(domain);
    return n === null ? false : this.entries.delete(n);
  }

  /** Returns the most specific matching rule for a hostname/URL, or null. */
  match(target: string): DomainRuleEntry | null {
    const host = normalizeHostname(target);
    return host === null ? null : this.matchNormalized(host);
  }

  /** Like match() but expects an already-normalized hostname (hot path). */
  matchNormalized(host: string): DomainRuleEntry | null {
    const exact = this.entries.get(host);
    if (exact) return exact;
    if (isIpLiteral(host)) return null;
    let idx = host.indexOf('.');
    while (idx !== -1) {
      const e = this.entries.get(host.slice(idx + 1));
      if (e?.includeSubdomains) return e;
      idx = host.indexOf('.', idx + 1);
    }
    return null;
  }

  list(): DomainRuleEntry[] {
    return [...this.entries.values()].sort((a, b) => a.domain.localeCompare(b.domain));
  }
}
