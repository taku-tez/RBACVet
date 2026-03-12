import type { Rule, RuleContext, Violation } from '../types';
import { hasAnyVerb, hasResource, resourceLabel, WRITE_VERBS } from '../utils';
import type { Role } from '../../parser/types';

function allRoles(ctx: RuleContext): Role[] {
  return [...ctx.graph.roles.values(), ...ctx.graph.clusterRoles.values()];
}

export const RB9001: Rule = {
  id: 'RB9001',
  severity: 'high',
  description: 'Role grants write access to `nodes/status` — allows faking node conditions (Ready, MemoryPressure, etc.)',
  cisId: 'CIS 5.1.3',
  check(ctx: RuleContext): Violation[] {
    const violations: Violation[] = [];
    for (const role of allRoles(ctx)) {
      for (const rule of role.rules) {
        if (hasResource(rule, 'nodes/status') && hasAnyVerb(rule, WRITE_VERBS)) {
          violations.push({
            rule: 'RB9001',
            severity: 'high',
            message: `${resourceLabel(role)} can write nodes/status — allows falsifying node conditions (Ready, MemoryPressure, DiskPressure), causing the scheduler to misplace or evict workloads`,
            resource: resourceLabel(role),
            file: role.sourceFile,
            line: role.sourceLine,
          });
          break;
        }
      }
    }
    return violations;
  },
};

export const RB9002: Rule = {
  id: 'RB9002',
  severity: 'medium',
  description: 'Role grants write access to `pods/status` — allows faking pod readiness and conditions',
  check(ctx: RuleContext): Violation[] {
    const violations: Violation[] = [];
    for (const role of allRoles(ctx)) {
      for (const rule of role.rules) {
        if (hasResource(rule, 'pods/status') && hasAnyVerb(rule, WRITE_VERBS)) {
          violations.push({
            rule: 'RB9002',
            severity: 'medium',
            message: `${resourceLabel(role)} can write pods/status — allows falsifying pod readiness/phase to trick load balancers and operators into routing traffic to unhealthy pods`,
            resource: resourceLabel(role),
            file: role.sourceFile,
            line: role.sourceLine,
          });
          break;
        }
      }
    }
    return violations;
  },
};

export const RB9003: Rule = {
  id: 'RB9003',
  severity: 'medium',
  description: 'Role grants write access to `resourcequotas` — allows inflating namespace limits for resource exhaustion',
  check(ctx: RuleContext): Violation[] {
    const violations: Violation[] = [];
    for (const role of allRoles(ctx)) {
      for (const rule of role.rules) {
        if (hasResource(rule, 'resourcequotas') && hasAnyVerb(rule, WRITE_VERBS)) {
          violations.push({
            rule: 'RB9003',
            severity: 'medium',
            message: `${resourceLabel(role)} can write ResourceQuotas — allows removing or inflating namespace resource limits, enabling resource exhaustion attacks against other tenants`,
            resource: resourceLabel(role),
            file: role.sourceFile,
            line: role.sourceLine,
          });
          break;
        }
      }
    }
    return violations;
  },
};

export const RB9004: Rule = {
  id: 'RB9004',
  severity: 'low',
  description: 'Role grants write access to `limitranges` — allows modifying per-namespace container limit constraints',
  check(ctx: RuleContext): Violation[] {
    const violations: Violation[] = [];
    for (const role of allRoles(ctx)) {
      for (const rule of role.rules) {
        if (hasResource(rule, 'limitranges') && hasAnyVerb(rule, WRITE_VERBS)) {
          violations.push({
            rule: 'RB9004',
            severity: 'low',
            message: `${resourceLabel(role)} can write LimitRanges — allows removing default memory/CPU limits, enabling containers to consume unbounded resources`,
            resource: resourceLabel(role),
            file: role.sourceFile,
            line: role.sourceLine,
          });
          break;
        }
      }
    }
    return violations;
  },
};

export const RB9_RULES: Rule[] = [RB9001, RB9002, RB9003, RB9004];
