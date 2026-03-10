import type { Rule, RuleContext, Violation } from '../types';
import type { AuthorizationPolicy } from '../../parser/types';

function policyLabel(p: AuthorizationPolicy): string {
  const ns = p.metadata.namespace ? `/${p.metadata.namespace}` : '';
  return `AuthorizationPolicy${ns}/${p.metadata.name}`;
}

export const IS1001: Rule = {
  id: 'IS1001',
  severity: 'high',
  description: 'AuthorizationPolicy ALLOW with no rules (allows all traffic)',
  check(ctx: RuleContext): Violation[] {
    const violations: Violation[] = [];
    for (const policy of ctx.graph.authorizationPolicies) {
      const action = policy.spec.action ?? 'ALLOW';
      if (action === 'ALLOW' && (!policy.spec.rules || policy.spec.rules.length === 0)) {
        violations.push({
          rule: 'IS1001',
          severity: 'high',
          message: `${policyLabel(policy)} has action ALLOW with no rules — allows all traffic to matched workloads`,
          resource: policyLabel(policy),
          file: policy.sourceFile,
          line: policy.sourceLine,
        });
      }
    }
    return violations;
  },
};

export const IS1002: Rule = {
  id: 'IS1002',
  severity: 'medium',
  description: 'Wildcard principal in AuthorizationPolicy (allows any identity)',
  check(ctx: RuleContext): Violation[] {
    const violations: Violation[] = [];
    for (const policy of ctx.graph.authorizationPolicies) {
      const action = policy.spec.action ?? 'ALLOW';
      // Only flag ALLOW policies (DENY with * is intentional: deny-all-then-allow pattern)
      if (action === 'DENY') continue; // skip
      for (const rule of policy.spec.rules ?? []) {
        for (const from of rule.from ?? []) {
          if (from.source.principals?.includes('*')) {
            violations.push({
              rule: 'IS1002',
              severity: 'medium',
              message: `${policyLabel(policy)} has wildcard principal '*' — allows any authenticated identity`,
              resource: policyLabel(policy),
              file: policy.sourceFile,
              line: policy.sourceLine,
            });
          }
        }
      }
    }
    return violations;
  },
};

export const IS1003: Rule = {
  id: 'IS1003',
  severity: 'medium',
  description: 'Wildcard HTTP method in AuthorizationPolicy',
  check(ctx: RuleContext): Violation[] {
    const violations: Violation[] = [];
    for (const policy of ctx.graph.authorizationPolicies) {
      for (const rule of policy.spec.rules ?? []) {
        for (const to of rule.to ?? []) {
          if (to.operation.methods?.includes('*')) {
            violations.push({
              rule: 'IS1003',
              severity: 'medium',
              message: `${policyLabel(policy)} allows wildcard HTTP method '*' — consider restricting to specific methods`,
              resource: policyLabel(policy),
              file: policy.sourceFile,
              line: policy.sourceLine,
            });
          }
        }
      }
    }
    return violations;
  },
};

export const IS1004: Rule = {
  id: 'IS1004',
  severity: 'info',
  description: 'Wildcard namespace in AuthorizationPolicy source',
  check(ctx: RuleContext): Violation[] {
    const violations: Violation[] = [];
    for (const policy of ctx.graph.authorizationPolicies) {
      for (const rule of policy.spec.rules ?? []) {
        for (const from of rule.from ?? []) {
          if (from.source.namespaces?.includes('*')) {
            violations.push({
              rule: 'IS1004',
              severity: 'info',
              message: `${policyLabel(policy)} allows traffic from wildcard namespace '*' — consider restricting to specific namespaces`,
              resource: policyLabel(policy),
              file: policy.sourceFile,
              line: policy.sourceLine,
            });
          }
        }
      }
    }
    return violations;
  },
};

export const IS1_RULES: Rule[] = [IS1001, IS1002, IS1003, IS1004];
