import { readFileSync } from 'node:fs';
import { validateRuleDomain } from '@savinggrace/domain-matcher';
import type { DomainRuleEntry } from '@savinggrace/shared-types';

export interface GlobalDomainList {
  readonly version: number;
  readonly updated: string;
  readonly entries: readonly DomainRuleEntry[];
}

export class GlobalListError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'GlobalListError';
  }
}

/**
 * Parses and validates the global adult-domain database (schema v1: string
 * domains, v2: objects with category). Any invalid entry rejects the whole
 * file: a partially loaded list would silently weaken protection.
 */
export function parseGlobalList(raw: unknown): GlobalDomainList {
  if (raw === null || typeof raw !== 'object') throw new GlobalListError('list must be a JSON object');
  const o = raw as Record<string, unknown>;
  const version = o.version;
  if (version !== 1 && version !== 2) throw new GlobalListError(`unsupported list version ${String(version)}`);
  if (typeof o.updated !== 'string' || !/^\d{4}-\d{2}-\d{2}$/.test(o.updated)) {
    throw new GlobalListError('"updated" must be YYYY-MM-DD');
  }
  if (!Array.isArray(o.domains)) throw new GlobalListError('"domains" must be an array');

  const entries: DomainRuleEntry[] = [];
  o.domains.forEach((d: unknown, i: number) => {
    let domain: unknown;
    let category = 'adult';
    if (version === 1) {
      domain = d;
    } else {
      if (d === null || typeof d !== 'object') throw new GlobalListError(`domains[${i}] must be an object`);
      const e = d as Record<string, unknown>;
      domain = e.domain;
      if (e.category !== undefined) {
        if (typeof e.category !== 'string' || e.category === '') throw new GlobalListError(`domains[${i}].category invalid`);
        category = e.category;
      }
    }
    if (typeof domain !== 'string') throw new GlobalListError(`domains[${i}] has no domain string`);
    const v = validateRuleDomain(domain, true);
    if (!v.ok) throw new GlobalListError(`domains[${i}] "${domain}": ${v.reason}`);
    entries.push({ domain: v.domain, includeSubdomains: v.includeSubdomains, category });
  });
  return { version, updated: o.updated, entries };
}

export function loadGlobalListFile(path: string): GlobalDomainList {
  let json: unknown;
  try {
    json = JSON.parse(readFileSync(path, 'utf8'));
  } catch (err) {
    throw new GlobalListError(`cannot read ${path}: ${err instanceof Error ? err.message : String(err)}`);
  }
  return parseGlobalList(json);
}
