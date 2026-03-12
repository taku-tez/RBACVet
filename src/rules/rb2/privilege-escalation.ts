import type { Rule, RuleContext, Violation, ResourceGraph } from '../types';
import { hasVerb, hasAnyVerb, hasResource, resourceLabel, bindingLabel, makeRoleKey, isClusterAdminEquivalent, WRITE_VERBS } from '../utils';
import type { Role, RoleBinding } from '../../parser/types';
import { findIndirectEscalationPaths } from '../../graph/paths';

function allRoles(ctx: RuleContext): Role[] {
  return [...ctx.graph.roles.values(), ...ctx.graph.clusterRoles.values()];
}

export const RB2001: Rule = {
  id: 'RB2001',
  severity: 'critical',
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
          severity: 'critical',
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
  severity: 'critical',
  description: 'Role with `escalate` verb',
  cisId: 'CIS 5.1.8',
  check(ctx: RuleContext): Violation[] {
    const violations: Violation[] = [];
    for (const role of allRoles(ctx)) {
      for (const rule of role.rules) {
        if (hasVerb(rule, 'escalate')) {
          violations.push({
            rule: 'RB2002',
            severity: 'critical',
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
  severity: 'high',
  description: 'Role with `bind` verb',
  cisId: 'CIS 5.1.8',
  check(ctx: RuleContext): Violation[] {
    const violations: Violation[] = [];
    for (const role of allRoles(ctx)) {
      for (const rule of role.rules) {
        if (hasVerb(rule, 'bind')) {
          violations.push({
            rule: 'RB2003',
            severity: 'high',
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
  severity: 'high',
  description: 'Role can modify Role/ClusterRole (RBAC management)',
  cisId: 'CIS 5.1.8',
  check(ctx: RuleContext): Violation[] {
    const violations: Violation[] = [];
    for (const role of allRoles(ctx)) {
      for (const rule of role.rules) {
        const targetsRoles = rule.resources.includes('roles') || rule.resources.includes('clusterroles') || rule.resources.includes('*');
        const hasWrite = WRITE_VERBS.some(v => hasVerb(rule, v));
        if (targetsRoles && hasWrite) {
          violations.push({
            rule: 'RB2004',
            severity: 'high',
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
  severity: 'high',
  description: 'Role can modify RoleBinding/ClusterRoleBinding',
  cisId: 'CIS 5.1.8',
  check(ctx: RuleContext): Violation[] {
    const violations: Violation[] = [];
    for (const role of allRoles(ctx)) {
      for (const rule of role.rules) {
        const targetsBindings = rule.resources.includes('rolebindings') || rule.resources.includes('clusterrolebindings') || rule.resources.includes('*');
        const hasWrite = WRITE_VERBS.some(v => hasVerb(rule, v));
        if (targetsBindings && hasWrite) {
          violations.push({
            rule: 'RB2005',
            severity: 'high',
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
  severity: 'high',
  description: 'Impersonation permissions (users, groups, serviceaccounts)',
  cisId: 'CIS 5.1.8',
  check(ctx: RuleContext): Violation[] {
    const violations: Violation[] = [];
    const impersonateResources = ['users', 'groups', 'serviceaccounts'];
    for (const role of allRoles(ctx)) {
      for (const rule of role.rules) {
        const targetsImpersonate = impersonateResources.some(r => hasResource(rule, r));
        if (targetsImpersonate && hasVerb(rule, 'impersonate')) {
          violations.push({
            rule: 'RB2006',
            severity: 'high',
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
  severity: 'high',
  description: 'Role grants access to `tokenreviews` or `subjectaccessreviews`',
  cisId: 'CIS 5.1.8',
  check(ctx: RuleContext): Violation[] {
    const violations: Violation[] = [];
    const authResources = ['tokenreviews', 'subjectaccessreviews'];
    for (const role of allRoles(ctx)) {
      for (const rule of role.rules) {
        if (authResources.some(r => hasResource(rule, r))) {
          violations.push({
            rule: 'RB2007',
            severity: 'high',
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

// RB2008 and RB2009 removed — superseded by RB7001 (admission-webhooks.ts)
// which covers both validating/mutating webhooks at higher severity (high vs medium)
// and also catches the delete verb (disabling webhooks entirely).

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
  severity: 'high',
  description: 'Detected privilege escalation chain (A → B → cluster-admin)',
  cisId: 'CIS 5.1.1',
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
          severity: 'high',
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
        severity: 'high',
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
  severity: 'medium',
  description: 'Role grants write access to ValidatingAdmissionPolicies (Kubernetes 1.26+)',
  cisId: 'CIS 5.1.3',
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
            severity: 'medium',
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

export const RB2012: Rule = {
  id: 'RB2012',
  severity: 'high',
  description: 'Role can approve CertificateSigningRequests — allows issuing certificates for arbitrary identities',
  cisId: 'CIS 5.1.8',
  check(ctx: RuleContext): Violation[] {
    const violations: Violation[] = [];
    for (const role of allRoles(ctx)) {
      let flagged = false;
      for (const rule of role.rules) {
        const csrApiGroup =
          rule.apiGroups.includes('certificates.k8s.io') || rule.apiGroups.includes('*');
        // Pattern 1: update/patch on certificatesigningrequests/approval subresource
        const approvalSubresource = hasResource(rule, 'certificatesigningrequests/approval');
        if (csrApiGroup && approvalSubresource && hasAnyVerb(rule, ['update', 'patch'])) {
          flagged = true;
          break;
        }
        // Pattern 2: approve verb on signers resource
        const signers = hasResource(rule, 'signers');
        if (csrApiGroup && signers && hasVerb(rule, 'approve')) {
          flagged = true;
          break;
        }
      }
      if (flagged) {
        violations.push({
          rule: 'RB2012',
          severity: 'high',
          message: `${resourceLabel(role)} can approve CertificateSigningRequests — allows issuing TLS certificates for any identity including cluster-admin`,
          resource: resourceLabel(role),
          file: role.sourceFile,
          line: role.sourceLine,
        });
      }
    }
    return violations;
  },
};

export const RB2_RULES: Rule[] = [
  RB2001, RB2002, RB2003, RB2004, RB2005,
  RB2006, RB2007, RB2010, RB2011, RB2012,
];
