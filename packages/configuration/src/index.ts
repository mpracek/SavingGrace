import { readFileSync } from 'node:fs';
import type { AppConfig, InvalidInputPolicy } from '@savinggrace/shared-types';

export const DEFAULT_CONFIG: AppConfig = Object.freeze({
  temporaryDisableEnabled: true,
  disableChallengeWordCount: 50,
  disableDurationsMinutes: Object.freeze([5, 15, 30, 60]),
  disableChallengeMaxFailedAttempts: 3,
  attemptRetentionDays: 90,
  onInvalidInput: 'allow',
  uiLanguage: 'sl',
  dnsEnabled: true,
  dnsListen: Object.freeze(['127.0.0.1:53', '[::1]:53']),
  dnsUpstreams: Object.freeze([]),
  enforceSystemProtection: true,
});

export class ConfigError extends Error {
  constructor(public readonly problems: readonly string[]) {
    super(`Invalid configuration: ${problems.join('; ')}`);
    this.name = 'ConfigError';
  }
}

const isInt = (v: unknown, min: number, max: number): v is number =>
  typeof v === 'number' && Number.isInteger(v) && v >= min && v <= max;

const IPV4 = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;

function isIpv4(s: string): boolean {
  const m = IPV4.exec(s);
  return m !== null && m.slice(1).every((o) => Number(o) <= 255);
}

function splitHostPort(s: string): { host: string; port: string | null } | null {
  if (s.startsWith('[')) {
    const m = /^\[([0-9a-fA-F:.]+)\](?::(\d{1,5}))?$/.exec(s);
    return m ? { host: m[1] as string, port: m[2] ?? null } : null;
  }
  const idx = s.lastIndexOf(':');
  if (idx !== -1 && s.indexOf(':') === idx) return { host: s.slice(0, idx), port: s.slice(idx + 1) };
  return { host: s, port: null };
}

const portOk = (p: string | null) => p === null || (/^\d{1,5}$/.test(p) && Number(p) >= 0 && Number(p) <= 65535);
const isIpv6 = (h: string) => h.includes(':') && /^[0-9a-fA-F:.]+$/.test(h);

function isLoopbackSocketAddr(s: string): boolean {
  const hp = splitHostPort(s);
  if (!hp || hp.port === null || !portOk(hp.port)) return false;
  return hp.host === '::1' || (isIpv4(hp.host) && hp.host.startsWith('127.'));
}

function isUpstream(s: string): boolean {
  const hp = splitHostPort(s);
  if (!hp || !portOk(hp.port)) return false;
  if (isIpv4(hp.host)) return !hp.host.startsWith('127.') && hp.host !== '0.0.0.0';
  return isIpv6(hp.host) && hp.host !== '::1' && hp.host !== '::';
}

/**
 * Merges a partial user config over the defaults and validates it strictly.
 * Unknown keys and out-of-range values are errors (never silently ignored).
 */
export function parseConfig(raw: unknown): AppConfig {
  if (raw === null || typeof raw !== 'object' || Array.isArray(raw)) {
    throw new ConfigError(['configuration must be a JSON object']);
  }
  const input = raw as Record<string, unknown>;
  const problems: string[] = [];
  const known = new Set(Object.keys(DEFAULT_CONFIG));
  for (const k of Object.keys(input)) if (!known.has(k)) problems.push(`unknown key "${k}"`);

  const out: { -readonly [K in keyof AppConfig]: AppConfig[K] } = { ...DEFAULT_CONFIG };

  if ('temporaryDisableEnabled' in input) {
    if (typeof input.temporaryDisableEnabled === 'boolean') out.temporaryDisableEnabled = input.temporaryDisableEnabled;
    else problems.push('temporaryDisableEnabled must be a boolean');
  }
  if ('disableChallengeWordCount' in input) {
    if (isInt(input.disableChallengeWordCount, 10, 100)) out.disableChallengeWordCount = input.disableChallengeWordCount;
    else problems.push('disableChallengeWordCount must be an integer 10..100');
  }
  if ('disableDurationsMinutes' in input) {
    const d = input.disableDurationsMinutes;
    if (Array.isArray(d) && d.length > 0 && d.every((x) => isInt(x, 1, 240))) {
      out.disableDurationsMinutes = [...new Set(d as number[])].sort((a, b) => a - b);
    } else problems.push('disableDurationsMinutes must be a non-empty array of integers 1..240');
  }
  if ('disableChallengeMaxFailedAttempts' in input) {
    if (isInt(input.disableChallengeMaxFailedAttempts, 1, 20)) out.disableChallengeMaxFailedAttempts = input.disableChallengeMaxFailedAttempts;
    else problems.push('disableChallengeMaxFailedAttempts must be an integer 1..20');
  }
  if ('attemptRetentionDays' in input) {
    if (isInt(input.attemptRetentionDays, 1, 3650)) out.attemptRetentionDays = input.attemptRetentionDays;
    else problems.push('attemptRetentionDays must be an integer 1..3650');
  }
  if ('onInvalidInput' in input) {
    const v = input.onInvalidInput;
    if (v === 'allow' || v === 'block') out.onInvalidInput = v as InvalidInputPolicy;
    else problems.push('onInvalidInput must be "allow" or "block"');
  }

  if ('uiLanguage' in input) {
    const v = input.uiLanguage;
    if (v === 'sl' || v === 'en') out.uiLanguage = v;
    else problems.push('uiLanguage must be "sl" or "en"');
  }

  for (const key of ['dnsEnabled', 'enforceSystemProtection'] as const) {
    if (key in input) {
      if (typeof input[key] === 'boolean') out[key] = input[key] as boolean;
      else problems.push(`${key} must be a boolean`);
    }
  }
  if ('dnsListen' in input) {
    const v = input.dnsListen;
    if (Array.isArray(v) && v.length > 0 && v.every((a) => typeof a === 'string' && isLoopbackSocketAddr(a))) {
      out.dnsListen = [...(v as string[])];
    } else problems.push('dnsListen must be a non-empty array of loopback ip:port addresses');
  }
  if ('dnsUpstreams' in input) {
    const v = input.dnsUpstreams;
    if (Array.isArray(v) && v.every((a) => typeof a === 'string' && isUpstream(a))) out.dnsUpstreams = [...(v as string[])];
    else problems.push('dnsUpstreams must be an array of non-loopback IP addresses, optionally with :port');
  }

  if (problems.length > 0) throw new ConfigError(problems);
  return out;
}

/**
 * Loads config from a JSON file. A missing file yields the defaults;
 * an unreadable/invalid file throws (the caller decides the fail-safe behaviour).
 */
export function loadConfigFile(path: string): AppConfig {
  let text: string;
  try {
    text = readFileSync(path, 'utf8');
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === 'ENOENT') return { ...DEFAULT_CONFIG };
    throw err;
  }
  let json: unknown;
  try {
    json = JSON.parse(text);
  } catch {
    throw new ConfigError([`${path} is not valid JSON`]);
  }
  return parseConfig(json);
}
