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
  cisId: 'CIS 5.1.2',
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
  cisId: 'CIS 5.1.2',
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

export const RB3011: Rule = {
  id: 'RB3011',
  severity: 'high',
  description: 'Role can access `nodes/proxy` — grants full kubelet API access, bypassing pod-level RBAC',
  cisId: 'CIS 5.1.2',
  check(ctx: RuleContext): Violation[] {
    const violations: Violation[] = [];
    for (const role of allRoles(ctx)) {
      for (const rule of role.rules) {
        if (hasResource(rule, 'nodes/proxy') && rule.verbs.length > 0) {
          violations.push({
            rule: 'RB3011',
            severity: 'high',
            message: `${resourceLabel(role)} can access nodes/proxy — exposes the kubelet API (port 10250), allowing exec/logs on any pod on that node regardless of pod-level RBAC`,
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

export const RB3012: Rule = {
  id: 'RB3012',
  severity: 'medium',
  description: 'Role can use `pods/proxy` or `services/proxy` — HTTP proxy bypasses NetworkPolicies',
  check(ctx: RuleContext): Violation[] {
    const violations: Violation[] = [];
    const proxyResources = ['pods/proxy', 'services/proxy'];
    for (const role of allRoles(ctx)) {
      for (const rule of role.rules) {
        const matched = proxyResources.filter(r => hasResource(rule, r));
        if (matched.length > 0 && rule.verbs.length > 0) {
          violations.push({
            rule: 'RB3012',
            severity: 'medium',
            message: `${resourceLabel(role)} can use ${matched.join('/')} — allows HTTP proxying to internal services through kube-apiserver, bypassing NetworkPolicies`,
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

export const RB3010: Rule = {
  id: 'RB3010',
  severity: 'medium',
  description: 'Role can use `pods/portforward` — allows bypassing network policies',
  check(ctx: RuleContext): Violation[] {
    const violations: Violation[] = [];
    for (const role of allRoles(ctx)) {
      for (const rule of role.rules) {
        if (hasResource(rule, 'pods/portforward') && hasVerb(rule, 'create')) {
          violations.push({
            rule: 'RB3010',
            severity: 'medium',
            message: `${resourceLabel(role)} can use pods/portforward — allows direct access to pod services, bypassing NetworkPolicies`,
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
  RB3001, RB3002, RB3003, RB3004, RB3005, RB3006, RB3007, RB3008, RB3009, RB3010,
  RB3011, RB3012,
];
