import type { Rule, RuleContext, Violation } from '../types';
import { bindingLabel, makeRoleKey, resourceLabel, isSystemResource } from '../utils';

/**
 * Kubernetes/GKE bootstrap ClusterRoles that are intentionally bound to
 * system:unauthenticated. These only expose non-resource health/version
 * endpoints (GET /healthz /livez /readyz /version) and carry no k8s resource
 * access — binding them to unauthenticated users is safe and expected.
 */
const SAFE_UNAUTHENTICATED_ROLES = new Set([
  'system:public-info-viewer', // /healthz /livez /readyz /version (read-only, non-resource)
  'system:discovery',          // API group discovery endpoints
]);

export const RB5001: Rule = {
  id: 'RB5001',
  severity: 'critical',
  description: 'RoleBinding to `system:unauthenticated`',
  cisId: 'CIS 5.1.1',
  check(ctx: RuleContext): Violation[] {
    const violations: Violation[] = [];
    const allBindings = [...ctx.graph.roleBindings, ...ctx.graph.clusterRoleBindings];
    for (const b of allBindings) {
      const hasUnauth = b.subjects.some(s =>
        s.kind === 'Group' && s.name === 'system:unauthenticated'
      );
      if (!hasUnauth) continue;

      // Skip Kubernetes bootstrap bindings that only expose health/version endpoints.
      // These are intentional defaults required for LB health checks and monitoring.
      if (SAFE_UNAUTHENTICATED_ROLES.has(b.roleRef.name)) continue;

      violations.push({
        rule: 'RB5001',
        severity: 'critical',
        message: `${bindingLabel(b)} binds to 'system:unauthenticated' — grants access to anonymous users`,
        resource: bindingLabel(b),
        file: b.sourceFile,
        line: b.sourceLine,
      });
    }
    return violations;
  },
};

export const RB5002: Rule = {
  id: 'RB5002',
  severity: 'critical',
  description: 'RoleBinding to `system:anonymous`',
  cisId: 'CIS 5.1.1',
  check(ctx: RuleContext): Violation[] {
    const violations: Violation[] = [];
    const allBindings = [...ctx.graph.roleBindings, ...ctx.graph.clusterRoleBindings];
    for (const b of allBindings) {
      const hasAnon = b.subjects.some(s =>
        s.name === 'system:anonymous'
      );
      if (hasAnon) {
        violations.push({
          rule: 'RB5002',
          severity: 'critical',
          message: `${bindingLabel(b)} binds to 'system:anonymous' — grants access to unauthenticated users`,
          resource: bindingLabel(b),
          file: b.sourceFile,
          line: b.sourceLine,
        });
      }
    }
    return violations;
  },
};

export const RB5003: Rule = {
  id: 'RB5003',
  severity: 'medium',
  description: 'ClusterRoleBinding count exceeds threshold',
  check(ctx: RuleContext): Violation[] {
    const violations: Violation[] = [];
    const threshold = 50;
    const userBindings = ctx.graph.clusterRoleBindings.filter(
      b => !isSystemResource(b.metadata.name) && !isSystemResource(b.roleRef.name)
    );
    const count = userBindings.length;
    if (count > threshold) {
      violations.push({
        rule: 'RB5003',
        severity: 'medium',
        message: `Found ${count} user-defined ClusterRoleBindings (threshold: ${threshold}) — review cluster-wide permission grants`,
        resource: 'ClusterRoleBinding/*',
        file: userBindings[0]?.sourceFile || '',
        line: 1,
      });
    }
    return violations;
  },
};

export const RB5004: Rule = {
  id: 'RB5004',
  severity: 'medium',
  description: 'Multiple ClusterRoles with overlapping permissions',
  check(ctx: RuleContext): Violation[] {
    const violations: Violation[] = [];
    const clusterRoles = [...ctx.graph.clusterRoles.values()];

    // Build resource-verb fingerprint per role
    const fingerprints = new Map<string, string[]>();
    for (const role of clusterRoles) {
      const fp = role.rules
        .flatMap(r => r.apiGroups.flatMap(ag => r.resources.flatMap(res => r.verbs.map(v => `${ag}/${res}:${v}`))))
        .sort();
      fingerprints.set(role.metadata.name, fp);
    }

    // Check pairs for significant overlap (>50% of permissions shared)
    const reported = new Set<string>();
    for (let i = 0; i < clusterRoles.length; i++) {
      for (let j = i + 1; j < clusterRoles.length; j++) {
        const a = clusterRoles[i];
        const b = clusterRoles[j];
        const fpA = new Set(fingerprints.get(a.metadata.name) || []);
        const fpB = new Set(fingerprints.get(b.metadata.name) || []);
        if (fpA.size === 0 || fpB.size === 0) continue;

        const intersection = [...fpA].filter(x => fpB.has(x));
        const overlapRatio = intersection.length / Math.min(fpA.size, fpB.size);

        const key = [a.metadata.name, b.metadata.name].sort().join('|');
        if (overlapRatio >= 0.5 && !reported.has(key)) {
          reported.add(key);
          violations.push({
            rule: 'RB5004',
            severity: 'medium',
            message: `ClusterRole/${a.metadata.name} and ClusterRole/${b.metadata.name} have ${Math.round(overlapRatio * 100)}% overlapping permissions — consider consolidating`,
            resource: `ClusterRole/${a.metadata.name}`,
            file: a.sourceFile,
            line: a.sourceLine,
          });
        }
      }
    }
    return violations;
  },
};

export const RB5005: Rule = {
  id: 'RB5005',
  severity: 'info',
  description: 'Unused Role (no RoleBinding references it)',
  check(ctx: RuleContext): Violation[] {
    const violations: Violation[] = [];
    const allBindings = [...ctx.graph.roleBindings, ...ctx.graph.clusterRoleBindings];
    const referencedRoles = new Set<string>();

    for (const b of allBindings) {
      const ns = b.metadata.namespace;
      if (b.roleRef.kind === 'Role') {
        referencedRoles.add(makeRoleKey(b.roleRef.name, ns));
      } else {
        referencedRoles.add(b.roleRef.name);
      }
    }

    // Check namespaced Roles
    for (const [key, role] of ctx.graph.roles) {
      if (!referencedRoles.has(key)) {
        violations.push({
          rule: 'RB5005',
          severity: 'info',
          message: `${resourceLabel(role)} is not referenced by any RoleBinding`,
          resource: resourceLabel(role),
          file: role.sourceFile,
          line: role.sourceLine,
        });
      }
    }

    // Check ClusterRoles (skip system: roles)
    for (const [name, role] of ctx.graph.clusterRoles) {
      if (name.startsWith('system:')) continue;
      if (!referencedRoles.has(name)) {
        violations.push({
          rule: 'RB5005',
          severity: 'info',
          message: `${resourceLabel(role)} is not referenced by any RoleBinding or ClusterRoleBinding`,
          resource: resourceLabel(role),
          file: role.sourceFile,
          line: role.sourceLine,
        });
      }
    }

    return violations;
  },
};

export const RB5006: Rule = {
  id: 'RB5006',
  severity: 'info',
  description: 'Orphaned RoleBinding (references non-existent Role)',
  check(ctx: RuleContext): Violation[] {
    const violations: Violation[] = [];

    for (const b of ctx.graph.roleBindings) {
      const ns = b.metadata.namespace;
      let exists: boolean;
      if (b.roleRef.kind === 'ClusterRole') {
        exists = ctx.graph.clusterRoles.has(b.roleRef.name);
      } else {
        exists = ctx.graph.roles.has(makeRoleKey(b.roleRef.name, ns));
      }
      if (!exists) {
        violations.push({
          rule: 'RB5006',
          severity: 'info',
          message: `${bindingLabel(b)} references ${b.roleRef.kind}/${b.roleRef.name} which was not found in scanned manifests`,
          resource: bindingLabel(b),
          file: b.sourceFile,
          line: b.sourceLine,
        });
      }
    }

    for (const b of ctx.graph.clusterRoleBindings) {
      const exists = ctx.graph.clusterRoles.has(b.roleRef.name) ||
        b.roleRef.name === 'cluster-admin';
      if (!exists) {
        violations.push({
          rule: 'RB5006',
          severity: 'info',
          message: `${bindingLabel(b)} references ClusterRole/${b.roleRef.name} which was not found in scanned manifests`,
          resource: bindingLabel(b),
          file: b.sourceFile,
          line: b.sourceLine,
        });
      }
    }

    return violations;
  },
};

export const RB5007: Rule = {
  id: 'RB5007',
  severity: 'medium',
  description: 'RoleBinding to `system:authenticated` group (all authenticated users)',
  check(ctx: RuleContext): Violation[] {
    const violations: Violation[] = [];
    const allBindings = [...ctx.graph.roleBindings, ...ctx.graph.clusterRoleBindings];
    for (const b of allBindings) {
      if (b.subjects.some(s => s.kind === 'Group' && s.name === 'system:authenticated')) {
        violations.push({
          rule: 'RB5007',
          severity: 'medium',
          message: `${bindingLabel(b)} binds to 'system:authenticated' — grants permissions to ALL authenticated users in the cluster`,
          resource: bindingLabel(b),
          file: b.sourceFile,
          line: b.sourceLine,
        });
      }
    }
    return violations;
  },
};

export const RB5008: Rule = {
  id: 'RB5008',
  severity: 'medium',
  description: 'Role grants write access to `leases` — can disrupt leader election for control plane components',
  check(ctx: RuleContext): Violation[] {
    const violations: Violation[] = [];
    const allRolesList = [...ctx.graph.roles.values(), ...ctx.graph.clusterRoles.values()];
    const writeVerbs = ['create', 'update', 'patch', 'delete', 'deletecollection'];
    for (const role of allRolesList) {
      for (const rule of role.rules) {
        const coordinationGroup =
          rule.apiGroups.includes('coordination.k8s.io') || rule.apiGroups.includes('*');
        const targetsLeases =
          rule.resources.includes('leases') || rule.resources.includes('*');
        const hasWrite = writeVerbs.some(v => rule.verbs.includes(v) || rule.verbs.includes('*'));
        if (coordinationGroup && targetsLeases && hasWrite) {
          violations.push({
            rule: 'RB5008',
            severity: 'medium',
            message: `${resourceLabel(role)} can write to leases (coordination.k8s.io) — can disrupt leader election for kube-controller-manager, kube-scheduler, or cloud-controller-manager`,
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

export const RB5_RULES: Rule[] = [
  RB5001, RB5002, RB5003, RB5004, RB5005, RB5006, RB5007, RB5008,
];
