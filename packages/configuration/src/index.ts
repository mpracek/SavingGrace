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
});

export class ConfigError extends Error {
  constructor(public readonly problems: readonly string[]) {
    super(`Invalid configuration: ${problems.join('; ')}`);
    this.name = 'ConfigError';
  }
}

const isInt = (v: unknown, min: number, max: number): v is number =>
  typeof v === 'number' && Number.isInteger(v) && v >= min && v <= max;

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
