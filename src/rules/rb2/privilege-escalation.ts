import type { Rule, RuleContext, Violation, ResourceGraph } from '../types';
import { hasVerb, hasResource, resourceLabel, bindingLabel, makeRoleKey, isClusterAdminEquivalent, WRITE_VERBS } from '../utils';
import type { Role, RoleBinding } from '../../parser/types';
import { findIndirectEscalationPaths } from '../../graph/paths';

function allRoles(ctx: RuleContext): Role[] {
  return [...ctx.graph.roles.values(), ...ctx.graph.clusterRoles.values()];
}

export const RB2001: Rule = {
  id: 'RB2001',
  severity: 'error',
  description: 'ClusterRoleBinding binds to `cluster-admin`',
  cisId: 'CIS 5.1.1',
  check(ctx: RuleContext): Violation[] {
    const violations: Violation[] = [];
    const trusted = new Set(ctx.config.trustedClusterAdminBindings);
    for (const b of ctx.graph.clusterRoleBindings) {
      if (trusted.has(b.metadata.name)) continue;
      if (b.roleRef.name === 'cluster-admin') {
        violations.push({
          rule: 'RB2001',
          severity: 'error',
          message: `${bindingLabel(b)} binds to 'cluster-admin' — grants full cluster access`,
          resource: bindingLabel(b),
          file: b.sourceFile,
          line: b.sourceLine,
        });
      }
    }
    return violations;
  },
};

export const RB2002: Rule = {
  id: 'RB2002',
  severity: 'error',
  description: 'Role with `escalate` verb',
  check(ctx: RuleContext): Violation[] {
    const violations: Violation[] = [];
    for (const role of allRoles(ctx)) {
      for (const rule of role.rules) {
        if (hasVerb(rule, 'escalate')) {
          violations.push({
            rule: 'RB2002',
            severity: 'error',
            message: `${resourceLabel(role)} grants 'escalate' verb — allows privilege escalation`,
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

export const RB2003: Rule = {
  id: 'RB2003',
  severity: 'error',
  description: 'Role with `bind` verb',
  check(ctx: RuleContext): Violation[] {
    const violations: Violation[] = [];
    for (const role of allRoles(ctx)) {
      for (const rule of role.rules) {
        if (hasVerb(rule, 'bind')) {
          violations.push({
            rule: 'RB2003',
            severity: 'error',
            message: `${resourceLabel(role)} grants 'bind' verb — allows binding to higher-privileged roles`,
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

export const RB2004: Rule = {
  id: 'RB2004',
  severity: 'error',
  description: 'Role can modify Role/ClusterRole (RBAC management)',
  check(ctx: RuleContext): Violation[] {
    const violations: Violation[] = [];
    for (const role of allRoles(ctx)) {
      for (const rule of role.rules) {
        const targetsRoles = rule.resources.includes('roles') || rule.resources.includes('clusterroles') || rule.resources.includes('*');
        const hasWrite = WRITE_VERBS.some(v => hasVerb(rule, v));
        if (targetsRoles && hasWrite) {
          violations.push({
            rule: 'RB2004',
            severity: 'error',
            message: `${resourceLabel(role)} can modify Role/ClusterRole — allows RBAC manipulation`,
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

export const RB2005: Rule = {
  id: 'RB2005',
  severity: 'error',
  description: 'Role can modify RoleBinding/ClusterRoleBinding',
  check(ctx: RuleContext): Violation[] {
    const violations: Violation[] = [];
    for (const role of allRoles(ctx)) {
      for (const rule of role.rules) {
        const targetsBindings = rule.resources.includes('rolebindings') || rule.resources.includes('clusterrolebindings') || rule.resources.includes('*');
        const hasWrite = WRITE_VERBS.some(v => hasVerb(rule, v));
        if (targetsBindings && hasWrite) {
          violations.push({
            rule: 'RB2005',
            severity: 'error',
            message: `${resourceLabel(role)} can modify RoleBinding/ClusterRoleBinding — allows granting arbitrary permissions`,
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

export const RB2006: Rule = {
  id: 'RB2006',
  severity: 'error',
  description: 'Impersonation permissions (users, groups, serviceaccounts)',
  check(ctx: RuleContext): Violation[] {
    const violations: Violation[] = [];
    const impersonateResources = ['users', 'groups', 'serviceaccounts'];
    for (const role of allRoles(ctx)) {
      for (const rule of role.rules) {
        const targetsImpersonate = impersonateResources.some(r => hasResource(rule, r));
        if (targetsImpersonate && hasVerb(rule, 'impersonate')) {
          violations.push({
            rule: 'RB2006',
            severity: 'error',
            message: `${resourceLabel(role)} grants impersonation of users/groups/serviceaccounts`,
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

export const RB2007: Rule = {
  id: 'RB2007',
  severity: 'error',
  description: 'Role grants access to `tokenreviews` or `subjectaccessreviews`',
  check(ctx: RuleContext): Violation[] {
    const violations: Violation[] = [];
    const authResources = ['tokenreviews', 'subjectaccessreviews'];
    for (const role of allRoles(ctx)) {
      for (const rule of role.rules) {
        if (authResources.some(r => hasResource(rule, r))) {
          violations.push({
            rule: 'RB2007',
            severity: 'error',
            message: `${resourceLabel(role)} grants access to tokenreviews/subjectaccessreviews — can verify or bypass auth`,
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

export const RB2008: Rule = {
  id: 'RB2008',
  severity: 'warning',
  description: 'Role can create/update `ValidatingWebhookConfiguration`',
  check(ctx: RuleContext): Violation[] {
    const violations: Violation[] = [];
    const writeVerbs = ['create', 'update', 'patch'];
    for (const role of allRoles(ctx)) {
      for (const rule of role.rules) {
        const targetsWebhook = hasResource(rule, 'validatingwebhookconfigurations');
        const hasWrite = writeVerbs.some(v => hasVerb(rule, v));
        if (targetsWebhook && hasWrite) {
          violations.push({
            rule: 'RB2008',
            severity: 'warning',
            message: `${resourceLabel(role)} can create/update ValidatingWebhookConfiguration — can intercept API requests`,
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

export const RB2009: Rule = {
  id: 'RB2009',
  severity: 'warning',
  description: 'Role can create/update `MutatingWebhookConfiguration`',
  check(ctx: RuleContext): Violation[] {
    const violations: Violation[] = [];
    const writeVerbs = ['create', 'update', 'patch'];
    for (const role of allRoles(ctx)) {
      for (const rule of role.rules) {
        const targetsWebhook = hasResource(rule, 'mutatingwebhookconfigurations');
        const hasWrite = writeVerbs.some(v => hasVerb(rule, v));
        if (targetsWebhook && hasWrite) {
          violations.push({
            rule: 'RB2009',
            severity: 'warning',
            message: `${resourceLabel(role)} can create/update MutatingWebhookConfiguration — can modify API requests`,
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

function resolveRoleForBinding(binding: RoleBinding, graph: ResourceGraph): Role | undefined {
  if (binding.roleRef.kind === 'ClusterRole') {
    return graph.clusterRoles.get(binding.roleRef.name);
  }
  const ns = binding.metadata.namespace;
  const key = makeRoleKey(binding.roleRef.name, ns);
  return graph.roles.get(key);
}

export function findEscalationChain(
  saName: string,
  saNamespace: string,
  graph: ResourceGraph,
  trusted: Set<string>,
): string[] | null {
  const saKey = `${saNamespace}/${saName}`;
  const allBindings = [...graph.roleBindings, ...graph.clusterRoleBindings];

  // Find all bindings that include this SA
  const boundBindings = allBindings.filter(b =>
    b.subjects.some(s =>
      s.kind === 'ServiceAccount' && s.name === saName &&
      (s.namespace === saNamespace || b.kind === 'ClusterRoleBinding')
    )
  );

  for (const binding of boundBindings) {
    if (trusted.has(binding.metadata.name) && binding.roleRef.name === 'cluster-admin') {
      continue;
    }
    if (binding.roleRef.name === 'cluster-admin') {
      return [saKey, `${binding.roleRef.kind}/${binding.roleRef.name}`];
    }
    const role = resolveRoleForBinding(binding, graph);
    if (role && isClusterAdminEquivalent(role)) {
      return [saKey, `${binding.kind}/${binding.metadata.name}`, `${role.kind}/${role.metadata.name}`];
    }
  }
  return null;
}

export const RB2010: Rule = {
  id: 'RB2010',
  severity: 'error',
  description: 'Detected privilege escalation chain (A → B → cluster-admin)',
  check(ctx: RuleContext): Violation[] {
    const violations: Violation[] = [];
    const trusted = new Set(ctx.config.trustedClusterAdminBindings);

    for (const sa of ctx.graph.serviceAccounts.values()) {
      const ns = sa.metadata.namespace || 'default';
      const chain = findEscalationChain(sa.metadata.name, ns, ctx.graph, trusted);
      if (chain) {
        // Detect escalation type: bind/escalate verbs = direct RBAC escalation
        const allBindings = [...ctx.graph.roleBindings, ...ctx.graph.clusterRoleBindings];
        const boundBindings = allBindings.filter(b =>
          b.subjects.some(s =>
            s.kind === 'ServiceAccount' && s.name === sa.metadata.name &&
            (s.namespace === ns || b.kind === 'ClusterRoleBinding')
          )
        );
        let escalationType = 'direct RBAC escalation';
        for (const binding of boundBindings) {
          const role = binding.roleRef.kind === 'ClusterRole'
            ? ctx.graph.clusterRoles.get(binding.roleRef.name)
            : ctx.graph.roles.get(makeRoleKey(binding.roleRef.name, binding.metadata.namespace));
          if (role) {
            const hasBindOrEscalate = role.rules.some(r =>
              r.verbs.includes('bind') || r.verbs.includes('escalate')
            );
            if (hasBindOrEscalate) {
              escalationType = 'direct RBAC escalation';
              break;
            }
            const canModifyRoles = role.rules.some(r => {
              const targetsRoles =
                r.resources.includes('roles') ||
                r.resources.includes('clusterroles') ||
                r.resources.includes('rolebindings') ||
                r.resources.includes('clusterrolebindings') ||
                r.resources.includes('*');
              const hasWrite = WRITE_VERBS.some(v => r.verbs.includes(v) || r.verbs.includes('*'));
              return targetsRoles && hasWrite;
            });
            if (canModifyRoles) {
              escalationType = 'indirect escalation via role modification';
            }
          }
        }
        violations.push({
          rule: 'RB2010',
          severity: 'error',
          message: `ServiceAccount/${ns}/${sa.metadata.name} has privilege escalation path (${escalationType}): ${chain.join(' → ')}`,
          resource: `ServiceAccount/${ns}/${sa.metadata.name}`,
          file: sa.sourceFile,
          line: sa.sourceLine,
        });
      }
    }

    // Indirect escalation detection
    const indirectPaths = findIndirectEscalationPaths(ctx.graph);
    for (const p of indirectPaths) {
      violations.push({
        rule: 'RB2010',
        severity: 'error',
        message: `ServiceAccount '${p.serviceAccount}' can modify RoleBindings — indirect privilege escalation path: ${p.path.join(' → ')}`,
        resource: `ServiceAccount/${p.serviceAccount}`,
        file: '',
        line: 0,
      });
    }

    return violations;
  },
};

export const RB2011: Rule = {
  id: 'RB2011',
  severity: 'warning',
  description: 'Role grants write access to ValidatingAdmissionPolicies (Kubernetes 1.26+)',
  check(ctx: RuleContext): Violation[] {
    const violations: Violation[] = [];
    const allRolesList = [...ctx.graph.roles.values(), ...ctx.graph.clusterRoles.values()];
    for (const role of allRolesList) {
      for (const rule of role.rules) {
        const targets = rule.resources.includes('validatingadmissionpolicies') ||
                        rule.resources.includes('validatingadmissionpolicybindings') ||
                        rule.resources.includes('*');
        const apiOk = rule.apiGroups.includes('admissionregistration.k8s.io') || rule.apiGroups.includes('*');
        const hasWrite = WRITE_VERBS.some(v => rule.verbs.includes(v) || rule.verbs.includes('*'));
        if (targets && apiOk && hasWrite) {
          violations.push({
            rule: 'RB2011',
            severity: 'warning',
            message: `${resourceLabel(role)} can modify ValidatingAdmissionPolicies — can bypass admission control`,
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

export const RB2_RULES: Rule[] = [
  RB2001, RB2002, RB2003, RB2004, RB2005,
  RB2006, RB2007, RB2008, RB2009, RB2010, RB2011,
];
