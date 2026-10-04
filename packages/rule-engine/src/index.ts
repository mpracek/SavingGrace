import { DomainSet, normalizeHostname } from '@savinggrace/domain-matcher';
import type {
  Decision,
  DomainRuleEntry,
  InvalidInputPolicy,
  RuleRequest,
  RuleType,
} from '@savinggrace/shared-types';

/**
 * Fixed evaluation order. Not configurable on purpose: a configurable
 * priority would let a bad config silently turn the allowlist into a bypass.
 */
export const RULE_PRIORITY = [
  'allowlist',
  'custom_blocklist',
  'global_blocklist',
  'classifier',
  'default',
] as const satisfies readonly RuleType[];

export interface ClassifierContext {
  readonly hostname: string;
  readonly url?: string;
}

export interface ClassifierVerdict {
  readonly block: boolean;
  readonly category: string;
  /** 0..1 */
  readonly confidence: number;
  readonly reason: string;
}

/**
 * Extension point for future URL/title/text/image classifiers.
 * No classifier ships in Phase 1; the engine only runs those it is given.
 */
export interface Classifier {
  readonly id: string;
  classify(ctx: ClassifierContext): ClassifierVerdict | null | Promise<ClassifierVerdict | null>;
}

export interface RuleEngineOptions {
  readonly allowlist?: Iterable<DomainRuleEntry | string>;
  readonly customBlocklist?: Iterable<DomainRuleEntry | string>;
  readonly globalBlocklist?: Iterable<DomainRuleEntry | string>;
  readonly classifiers?: readonly Classifier[];
  readonly onInvalidInput?: InvalidInputPolicy;
}

/**
 * Immutable once built. To change rules, build a new engine and swap the
 * reference; this avoids half-updated state during evaluation.
 */
export class RuleEngine {
  private readonly allow: DomainSet;
  private readonly custom: DomainSet;
  private readonly global: DomainSet;
  private readonly classifiers: readonly Classifier[];
  private readonly onInvalid: InvalidInputPolicy;

  constructor(opts: RuleEngineOptions = {}) {
    this.allow = new DomainSet(opts.allowlist);
    this.custom = new DomainSet(opts.customBlocklist);
    this.global = new DomainSet(opts.globalBlocklist);
    this.classifiers = [...(opts.classifiers ?? [])];
    this.onInvalid = opts.onInvalidInput ?? 'allow';
  }

  /** Synchronous list-based decision (allowlist, custom, global). Classifiers are NOT run. */
  evaluate(req: RuleRequest): Decision {
    const host = normalizeHostname(req.target);
    if (host === null) return this.invalid();
    return this.listDecision(host) ?? this.defaultDecision(host, []);
  }

  /** Full pipeline including classifiers. Lists always win; classifiers only see unmatched hosts. */
  async evaluateAsync(req: RuleRequest): Promise<Decision> {
    const host = normalizeHostname(req.target);
    if (host === null) return this.invalid();
    const listed = this.listDecision(host);
    if (listed) return listed;

    const warnings: string[] = [];
    for (const c of this.classifiers) {
      try {
        const v = await c.classify({ hostname: host, url: req.target });
        if (v?.block) {
          return {
            action: 'BLOCK',
            ruleType: 'classifier',
            matchedRule: c.id,
            hostname: host,
            category: v.category,
            warnings,
          };
        }
      } catch (err) {
        // A broken classifier must not take protection down, nor silently vanish.
        warnings.push(`classifier ${c.id} failed: ${err instanceof Error ? err.message : String(err)}`);
      }
    }
    return this.defaultDecision(host, warnings);
  }

  private listDecision(host: string): Decision | null {
    const a = this.allow.matchNormalized(host);
    if (a) return this.make('ALLOW', 'allowlist', a, host);
    const c = this.custom.matchNormalized(host);
    if (c) return this.make('BLOCK', 'custom_blocklist', c, host);
    const g = this.global.matchNormalized(host);
    if (g) return this.make('BLOCK', 'global_blocklist', g, host);
    return null;
  }

  private make(action: 'ALLOW' | 'BLOCK', ruleType: RuleType, e: DomainRuleEntry, host: string): Decision {
    return {
      action,
      ruleType,
      matchedRule: e.domain,
      hostname: host,
      category: e.category ?? null,
      warnings: [],
    };
  }

  private defaultDecision(host: string, warnings: readonly string[]): Decision {
    return { action: 'ALLOW', ruleType: 'default', matchedRule: null, hostname: host, category: null, warnings };
  }

  private invalid(): Decision {
    return {
      action: this.onInvalid === 'block' ? 'BLOCK' : 'ALLOW',
      ruleType: 'invalid_input',
      matchedRule: null,
      hostname: null,
      category: null,
      warnings: [],
    };
  }
}
export * from './global-list.js';
