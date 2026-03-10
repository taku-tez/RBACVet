import type { Rule, RuleContext, Violation } from '../types';
import { hasWildcard, hasVerb, hasAnyVerb, hasResource, resourceLabel, WRITE_VERBS } from '../utils';
import type { Role, PolicyRule } from '../../parser/types';

function allRoles(ctx: RuleContext): Role[] {
  return [...ctx.graph.roles.values(), ...ctx.graph.clusterRoles.values()];
}

export const RB1001: Rule = {
  id: 'RB1001',
  severity: 'error',
  description: 'Wildcard `*` in verbs',
  cisId: 'CIS 5.1.3',
  check(ctx: RuleContext): Violation[] {
    const violations: Violation[] = [];
    for (const role of allRoles(ctx)) {
      for (const rule of role.rules) {
        if (hasWildcard(rule.verbs)) {
          violations.push({
            rule: 'RB1001',
            severity: 'error',
            message: `${resourceLabel(role)} has wildcard verb '*' — grants all actions`,
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

export const RB1002: Rule = {
  id: 'RB1002',
  severity: 'error',
  description: 'Wildcard `*` in resources',
  cisId: 'CIS 5.1.3',
  check(ctx: RuleContext): Violation[] {
    const violations: Violation[] = [];
    for (const role of allRoles(ctx)) {
      for (const rule of role.rules) {
        if (hasWildcard(rule.resources)) {
          violations.push({
            rule: 'RB1002',
            severity: 'error',
            message: `${resourceLabel(role)} has wildcard resource '*' — grants access to all resources`,
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

export const RB1003: Rule = {
  id: 'RB1003',
  severity: 'warning',
  description: 'Wildcard `*` in apiGroups',
  check(ctx: RuleContext): Violation[] {
    const violations: Violation[] = [];
    for (const role of allRoles(ctx)) {
      for (const rule of role.rules) {
        if (hasWildcard(rule.apiGroups)) {
          violations.push({
            rule: 'RB1003',
            severity: 'warning',
            message: `${resourceLabel(role)} has wildcard apiGroup '*' — grants access across all API groups`,
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

export const RB1004: Rule = {
  id: 'RB1004',
  severity: 'error',
  description: '`create` + `delete` combined on same resource',
  check(ctx: RuleContext): Violation[] {
    const violations: Violation[] = [];
    for (const role of allRoles(ctx)) {
      // Skip roles already caught by RB1001 (wildcard verbs)
      if (role.rules.some(r => r.verbs.includes('*'))) continue;
      const allVerbs = new Set(role.rules.flatMap(r => r.verbs));
      const hasCreate = allVerbs.has('create');
      const hasDelete = allVerbs.has('delete') || allVerbs.has('deletecollection');
      if (hasCreate && hasDelete) {
        violations.push({
          rule: 'RB1004',
          severity: 'error',
          message: `${resourceLabel(role)} combines 'create' and 'delete' on the same resource`,
          resource: resourceLabel(role),
          file: role.sourceFile,
          line: role.sourceLine,
        });
      }
    }
    return violations;
  },
};

export const RB1005: Rule = {
  id: 'RB1005',
  severity: 'warning',
  description: '`update` + `patch` combined with no resource restriction',
  check(ctx: RuleContext): Violation[] {
    const violations: Violation[] = [];
    for (const role of allRoles(ctx)) {
      // Skip roles already caught by RB1001 (wildcard verbs)
      if (role.rules.some(r => r.verbs.includes('*'))) continue;
      const allVerbs = new Set(role.rules.flatMap(r => r.verbs));
      const hasUpdate = allVerbs.has('update');
      const hasPatch = allVerbs.has('patch');
      if (hasUpdate && hasPatch) {
        violations.push({
          rule: 'RB1005',
          severity: 'warning',
          message: `${resourceLabel(role)} combines 'update' and 'patch' on all resources`,
          resource: resourceLabel(role),
          file: role.sourceFile,
          line: role.sourceLine,
        });
      }
    }
    return violations;
  },
};

export const RB1006: Rule = {
  id: 'RB1006',
  severity: 'error',
  description: 'ClusterRole with write access to all core resources',
  check(ctx: RuleContext): Violation[] {
    const violations: Violation[] = [];
    for (const role of ctx.graph.clusterRoles.values()) {
      for (const rule of role.rules) {
        const coreGroup = rule.apiGroups.includes('') || hasWildcard(rule.apiGroups);
        const allResources = hasWildcard(rule.resources);
        const hasWrite = hasAnyVerb(rule, ['create', 'update', 'patch', 'delete']);
        if (coreGroup && allResources && hasWrite) {
          violations.push({
            rule: 'RB1006',
            severity: 'error',
            message: `${resourceLabel(role)} (ClusterRole) grants write access to all core resources`,
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

export const RB1007: Rule = {
  id: 'RB1007',
  severity: 'info',
  description: 'Role grants `list` on all resources',
  check(ctx: RuleContext): Violation[] {
    const violations: Violation[] = [];
    for (const role of allRoles(ctx)) {
      for (const rule of role.rules) {
        if (hasVerb(rule, 'list') && hasWildcard(rule.resources)) {
          violations.push({
            rule: 'RB1007',
            severity: 'info',
            message: `${resourceLabel(role)} grants 'list' on all resources`,
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

export const RB1008: Rule = {
  id: 'RB1008',
  severity: 'info',
  description: 'Role grants `watch` on all resources',
  check(ctx: RuleContext): Violation[] {
    const violations: Violation[] = [];
    for (const role of allRoles(ctx)) {
      for (const rule of role.rules) {
        if (hasVerb(rule, 'watch') && hasWildcard(rule.resources)) {
          violations.push({
            rule: 'RB1008',
            severity: 'info',
            message: `${resourceLabel(role)} grants 'watch' on all resources`,
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

export const RB1009: Rule = {
  id: 'RB1009',
  severity: 'error',
  description: 'Role with `*` verbs on `nodes` resource',
  check(ctx: RuleContext): Violation[] {
    const violations: Violation[] = [];
    for (const role of allRoles(ctx)) {
      for (const rule of role.rules) {
        if (hasWildcard(rule.verbs) && hasResource(rule, 'nodes')) {
          violations.push({
            rule: 'RB1009',
            severity: 'error',
            message: `${resourceLabel(role)} grants all verbs on 'nodes' resource`,
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

export const RB1010: Rule = {
  id: 'RB1010',
  severity: 'error',
  description: 'Role with `*` verbs on `namespaces` resource',
  check(ctx: RuleContext): Violation[] {
    const violations: Violation[] = [];
    for (const role of allRoles(ctx)) {
      for (const rule of role.rules) {
        if (hasWildcard(rule.verbs) && hasResource(rule, 'namespaces')) {
          violations.push({
            rule: 'RB1010',
            severity: 'error',
            message: `${resourceLabel(role)} grants all verbs on 'namespaces' resource`,
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

export const RB1011: Rule = {
  id: 'RB1011',
  severity: 'warning',
  description: 'Role with `deletecollection` verb',
  check(ctx: RuleContext): Violation[] {
    const violations: Violation[] = [];
    for (const role of allRoles(ctx)) {
      for (const rule of role.rules) {
        if (hasVerb(rule, 'deletecollection')) {
          violations.push({
            rule: 'RB1011',
            severity: 'warning',
            message: `${resourceLabel(role)} grants 'deletecollection' verb — allows bulk deletion`,
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

export const RB1012: Rule = {
  id: 'RB1012',
  severity: 'info',
  description: 'Role with more than 20 permission rules',
  check(ctx: RuleContext): Violation[] {
    const violations: Violation[] = [];
    for (const role of allRoles(ctx)) {
      if (role.rules.length > 20) {
        violations.push({
          rule: 'RB1012',
          severity: 'info',
          message: `${resourceLabel(role)} has ${role.rules.length} permission rules — consider splitting into smaller roles`,
          resource: resourceLabel(role),
          file: role.sourceFile,
          line: role.sourceLine,
        });
      }
    }
    return violations;
  },
};

export const RB1_WRITE_ONLY: Rule = {
  id: 'RB1013',
  severity: 'info',
  description: 'Role has write-only access (no read verbs) — likely misconfiguration',
  check(ctx: RuleContext): Violation[] {
    const violations: Violation[] = [];
    const readVerbs = ['get', 'list', 'watch'];
    for (const role of allRoles(ctx)) {
      // Skip wildcard verbs (already covered by RB1001)
      if (role.rules.some(r => r.verbs.includes('*'))) continue;
      const allVerbs = new Set(role.rules.flatMap(r => r.verbs));
      const hasRead = readVerbs.some(v => allVerbs.has(v));
      const hasWrite = WRITE_VERBS.some(v => allVerbs.has(v));
      if (hasWrite && !hasRead && allVerbs.size > 0) {
        violations.push({
          rule: 'RB1013',
          severity: 'info',
          message: `${resourceLabel(role)} has write verbs but no read verbs — this is unusual and may indicate misconfiguration`,
          resource: resourceLabel(role),
          file: role.sourceFile,
          line: role.sourceLine,
        });
      }
    }
    return violations;
  },
};

export const RB1_RULES: Rule[] = [
  RB1001, RB1002, RB1003, RB1004, RB1005, RB1006,
  RB1007, RB1008, RB1009, RB1010, RB1011, RB1012, RB1_WRITE_ONLY,
];
