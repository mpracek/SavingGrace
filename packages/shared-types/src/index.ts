/** Final verdict of the rule engine for one request. */
export type RuleAction = 'ALLOW' | 'BLOCK';

/**
 * Which stage of the rule pipeline produced the decision.
 * `default` = nothing matched; `invalid_input` = hostname could not be parsed.
 */
export type RuleType =
  | 'allowlist'
  | 'custom_blocklist'
  | 'global_blocklist'
  | 'classifier'
  | 'default'
  | 'invalid_input';

/** One domain rule (allowlist, custom blocklist or global list entry). */
export interface DomainRuleEntry {
  /** Normalized (lowercase, punycode, no trailing dot) domain or IP literal. */
  readonly domain: string;
  /** If true the rule also covers every subdomain. Always false for IP literals. */
  readonly includeSubdomains: boolean;
  /** Optional category, e.g. "adult". */
  readonly category?: string;
}

/** What the rule engine is asked to judge. */
export interface RuleRequest {
  /** Hostname, host:port or full URL. Parsed and normalized by the engine. */
  readonly target: string;
  /** Originating process/browser, if known. Not used for decisions in Phase 1. */
  readonly process?: string;
}

export interface Decision {
  readonly action: RuleAction;
  readonly ruleType: RuleType;
  /** The rule domain (or classifier id) that matched; null for default/invalid. */
  readonly matchedRule: string | null;
  /** Normalized hostname, or null if the input could not be parsed. */
  readonly hostname: string | null;
  readonly category: string | null;
  /** Non-fatal problems, e.g. a classifier that threw. */
  readonly warnings: readonly string[];
}

/** Persisted record of a BLOCKED attempt. Allowed requests are never logged. */
export interface AccessAttempt {
  readonly id: number;
  /** ISO-8601 UTC timestamp. */
  readonly timestamp: string;
  readonly hostname: string;
  readonly matchedRule: string;
  readonly ruleType: Exclude<RuleType, 'default' | 'invalid_input' | 'allowlist'>;
  readonly action: 'BLOCK';
  readonly process: string | null;
  readonly category: string | null;
}

export type InvalidInputPolicy = 'allow' | 'block';

/** Admin UI language: Slovenian or English. */
export type UiLanguage = 'sl' | 'en';

export interface AppConfig {
  /** Feature flag. When false the temporary-disable feature must be unavailable. */
  readonly temporaryDisableEnabled: boolean;
  /** Number of Slovenian words the user must type (10..100). */
  readonly disableChallengeWordCount: number;
  /** Selectable disable durations in minutes. */
  readonly disableDurationsMinutes: readonly number[];
  /** Failed challenge attempts before the challenge is regenerated. */
  readonly disableChallengeMaxFailedAttempts: number;
  /** Blocked attempts older than this many days are purged. */
  readonly attemptRetentionDays: number;
  /** What to do with a target that cannot be parsed as a hostname. */
  readonly onInvalidInput: InvalidInputPolicy;
  /** Admin UI language. */
  readonly uiLanguage: UiLanguage;
}
