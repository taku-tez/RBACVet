import type { Violation } from '../rules/types';
import type { PolicyFile, ResolvedExemption, FilterResult } from './types';

function resolveExemption(e: import('./types').PolicyExemption, now: Date): ResolvedExemption {
  if (!e.expires) return { ...e, isExpired: false };

  const expiryDate = new Date(e.expires);
  const isExpired = expiryDate < now;
  const msPerDay = 1000 * 60 * 60 * 24;
  const daysUntilExpiry = Math.ceil((expiryDate.getTime() - now.getTime()) / msPerDay);

  return { ...e, isExpired, daysUntilExpiry: isExpired ? undefined : daysUntilExpiry };
}

function matchesExemption(violation: Violation, exemption: ResolvedExemption): boolean {
  const ruleMatch = exemption.rule === '*' || exemption.rule === violation.rule;
  const resourceMatch = exemption.resource === '*' || exemption.resource === violation.resource;
  return ruleMatch && resourceMatch && !exemption.isExpired;
}

export function applyExemptions(
  violations: Violation[],
  policy: PolicyFile | null,
  now: Date = new Date(),
): FilterResult {
  if (!policy || policy.exemptions.length === 0) {
    return { remaining: violations, exempted: [], expiredExemptions: [] };
  }

  const resolved = policy.exemptions.map(e => resolveExemption(e, now));
  const expiredExemptions = resolved.filter(e => e.isExpired);

  const remaining: Violation[] = [];
  const exempted: FilterResult['exempted'] = [];

  for (const violation of violations) {
    const matchingExemption = resolved.find(e => matchesExemption(violation, e));
    if (matchingExemption) {
      exempted.push({ violation, exemption: matchingExemption });
    } else {
      remaining.push(violation);
    }
  }

  return { remaining, exempted, expiredExemptions };
}
