import type { Violation, Rule } from './types';

export interface ViolationWithCIS extends Violation {
  cisId?: string;
}

export function enrichViolationsWithCIS(
  violations: Violation[],
  ruleMap: Map<string, Rule>,
): ViolationWithCIS[] {
  return violations.map(v => {
    const rule = ruleMap.get(v.rule);
    if (rule?.cisId) {
      return { ...v, cisId: rule.cisId };
    }
    return { ...v };
  });
}
