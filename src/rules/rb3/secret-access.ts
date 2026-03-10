import type { Rule, RuleContext, Violation } from '../types';
import { hasVerb, hasAnyVerb, hasResource, hasWildcard, resourceLabel, WRITE_VERBS } from '../utils';
import type { Role } from '../../parser/types';

function allRoles(ctx: RuleContext): Role[] {
  return [...ctx.graph.roles.values(), ...ctx.graph.clusterRoles.values()];
}

export const RB3001: Rule = {
  id: 'RB3001',
  severity: 'high',
  description: 'Role grants read access to `secrets`',
  cisId: 'CIS 5.1.2',
  check(ctx: RuleContext): Violation[] {
    const violations: Violation[] = [];
    const readVerbs = ['get', 'list', 'watch'];
    for (const role of allRoles(ctx)) {
      for (const rule of role.rules) {
        if (hasResource(rule, 'secrets') && readVerbs.some(v => hasVerb(rule, v))) {
          violations.push({
            rule: 'RB3001',
            severity: 'high',
            message: `${resourceLabel(role)} grants read access to 'secrets' (if this is a system component, consider using --include-system to suppress)`,
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

export const RB3002: Rule = {
  id: 'RB3002',
  severity: 'high',
  description: 'Role grants write access to `secrets`',
  cisId: 'CIS 5.1.2',
  check(ctx: RuleContext): Violation[] {
    const violations: Violation[] = [];
    for (const role of allRoles(ctx)) {
      for (const rule of role.rules) {
        if (hasResource(rule, 'secrets') && WRITE_VERBS.some(v => hasVerb(rule, v))) {
          violations.push({
            rule: 'RB3002',
            severity: 'high',
            message: `${resourceLabel(role)} grants write access to 'secrets' — can exfiltrate or tamper with credentials`,
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

export const RB3003: Rule = {
  id: 'RB3003',
  severity: 'medium',
  description: 'Role grants access to `configmaps` with write',
  check(ctx: RuleContext): Violation[] {
    const violations: Violation[] = [];
    for (const role of allRoles(ctx)) {
      for (const rule of role.rules) {
        if (hasResource(rule, 'configmaps') && WRITE_VERBS.some(v => hasVerb(rule, v))) {
          violations.push({
            rule: 'RB3003',
            severity: 'medium',
            message: `${resourceLabel(role)} grants write access to 'configmaps' — can inject configuration`,
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

export const RB3004: Rule = {
  id: 'RB3004',
  severity: 'high',
  description: 'Role can `exec` into pods (`pods/exec`)',
  check(ctx: RuleContext): Violation[] {
    const violations: Violation[] = [];
    for (const role of allRoles(ctx)) {
      for (const rule of role.rules) {
        if (hasResource(rule, 'pods/exec')) {
          violations.push({
            rule: 'RB3004',
            severity: 'high',
            message: `${resourceLabel(role)} can exec into pods — allows arbitrary command execution`,
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

export const RB3005: Rule = {
  id: 'RB3005',
  severity: 'medium',
  description: 'Role can `attach` to pods (`pods/attach`)',
  check(ctx: RuleContext): Violation[] {
    const violations: Violation[] = [];
    for (const role of allRoles(ctx)) {
      for (const rule of role.rules) {
        if (hasResource(rule, 'pods/attach')) {
          violations.push({
            rule: 'RB3005',
            severity: 'medium',
            message: `${resourceLabel(role)} can attach to pods — allows interacting with running containers`,
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

export const RB3006: Rule = {
  id: 'RB3006',
  severity: 'medium',
  description: 'Role can access pod logs (`pods/log`)',
  check(ctx: RuleContext): Violation[] {
    const violations: Violation[] = [];
    for (const role of allRoles(ctx)) {
      for (const rule of role.rules) {
        if (hasResource(rule, 'pods/log')) {
          violations.push({
            rule: 'RB3006',
            severity: 'medium',
            message: `${resourceLabel(role)} can access pod logs — may expose sensitive runtime data`,
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

export const RB3007: Rule = {
  id: 'RB3007',
  severity: 'critical',
  description: 'Role can access `etcd` directly',
  check(ctx: RuleContext): Violation[] {
    const violations: Violation[] = [];
    for (const role of allRoles(ctx)) {
      for (const rule of role.rules) {
        if (hasResource(rule, 'etcd') || hasResource(rule, 'etcdclusters')) {
          violations.push({
            rule: 'RB3007',
            severity: 'critical',
            message: `${resourceLabel(role)} can access etcd — grants access to all cluster data`,
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

export const RB3008: Rule = {
  id: 'RB3008',
  severity: 'medium',
  description: 'Role grants access to `persistentvolumes`',
  check(ctx: RuleContext): Violation[] {
    const violations: Violation[] = [];
    const pvResources = ['persistentvolumes', 'persistentvolumeclaims', 'volumeattachments'];
    for (const role of allRoles(ctx)) {
      for (const rule of role.rules) {
        const targetsPV = pvResources.some(r => rule.resources.includes(r) || rule.resources.includes('*'));
        if (targetsPV && hasAnyVerb(rule, ['get', 'list', 'create', 'update', 'patch', 'delete'])) {
          violations.push({
            rule: 'RB3008',
            severity: 'medium',
            message: `${resourceLabel(role)} can access persistent storage (PersistentVolumes/PVCs/VolumeAttachments)`,
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

export const RB3009: Rule = {
  id: 'RB3009',
  severity: 'high',
  description: 'Role accesses secrets via wildcard apiGroup — broad secret exposure',
  check(ctx: RuleContext): Violation[] {
    const violations: Violation[] = [];
    for (const role of allRoles(ctx)) {
      for (const rule of role.rules) {
        if (!rule.apiGroups.includes('*')) continue;
        if (!rule.resources.includes('secrets') && !rule.resources.includes('*')) continue;
        // RB3001/3002 already handles core ('') apiGroup; this catches wildcard group
        const hasAccess = rule.verbs.some(v => v !== '') || rule.verbs.includes('*');
        if (hasAccess) {
          violations.push({
            rule: 'RB3009',
            severity: 'high',
            message: `${resourceLabel(role)} accesses secrets via wildcard apiGroup — exposes secrets across all API groups`,
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

export const RB3_RULES: Rule[] = [
  RB3001, RB3002, RB3003, RB3004, RB3005, RB3006, RB3007, RB3008, RB3009,
];
