import type { Rule, RuleContext, Violation } from '../types';
import { bindingLabel } from '../utils';

export const RB6001: Rule = {
  id: 'RB6001',
  severity: 'medium',
  description: 'RoleBinding subjects a ServiceAccount from a different namespace',
  check(ctx: RuleContext): Violation[] {
    const violations: Violation[] = [];

    for (const b of ctx.graph.roleBindings) {
      const bindingNs = b.metadata.namespace;
      for (const subject of b.subjects) {
        if (subject.kind === 'ServiceAccount' && subject.namespace && bindingNs) {
          if (subject.namespace !== bindingNs) {
            violations.push({
              rule: 'RB6001',
              severity: 'medium',
              message: `${bindingLabel(b)} in namespace '${bindingNs}' subjects ServiceAccount '${subject.name}' from namespace '${subject.namespace}'`,
              resource: bindingLabel(b),
              file: b.sourceFile,
              line: b.sourceLine,
            });
            break;
          }
        }
      }
    }

    return violations;
  },
};

/**
 * The Kubernetes bootstrap `cluster-admin` CRB binding `system:masters` is
 * hardcoded in the API server and cannot be removed or modified at runtime.
 * It exists in every cluster by design. Flagging it as an error creates noise
 * with no actionable remediation — downgrade to info so it remains visible
 * but does not inflate the error count.
 *
 * Any *non-bootstrap* binding to system:masters is still reported as error.
 */
const K8S_BOOTSTRAP_MASTERS_BINDINGS = new Set([
  'cluster-admin', // kubernetes.io/bootstrapping: rbac-defaults — created by kube-apiserver
]);

export const RB6002: Rule = {
  id: 'RB6002',
  severity: 'critical',
  description: 'Binding to `system:masters` group (bypasses RBAC, cannot be revoked)',
  check(ctx: RuleContext): Violation[] {
    const violations: Violation[] = [];
    const allBindings = [...ctx.graph.roleBindings, ...ctx.graph.clusterRoleBindings];
    for (const b of allBindings) {
      if (b.subjects.some(s => s.kind === 'Group' && s.name === 'system:masters')) {
        const isBootstrap = K8S_BOOTSTRAP_MASTERS_BINDINGS.has(b.metadata.name);
        violations.push({
          rule: 'RB6002',
          severity: isBootstrap ? 'info' : 'critical',
          message: isBootstrap
            ? `${bindingLabel(b)} binds to 'system:masters' — Kubernetes bootstrap default (hardcoded in API server, cannot be removed)`
            : `${bindingLabel(b)} binds to 'system:masters' — this group bypasses RBAC entirely and cannot be revoked at runtime`,
          resource: bindingLabel(b),
          file: b.sourceFile,
          line: b.sourceLine,
        });
      }
    }
    return violations;
  },
};

export const RB6003: Rule = {
  id: 'RB6003',
  severity: 'medium',
  description: 'Role grants write access to `networkpolicies` (can break network isolation)',
  check(ctx: RuleContext): Violation[] {
    const violations: Violation[] = [];
    const allRoles = [...ctx.graph.roles.values(), ...ctx.graph.clusterRoles.values()];
    for (const role of allRoles) {
      for (const rule of role.rules) {
        const targetsNetpol = rule.resources.includes('networkpolicies') || rule.resources.includes('*');
        const hasWrite = ['create', 'update', 'patch', 'delete'].some(v =>
          rule.verbs.includes('*') || rule.verbs.includes(v)
        );
        if (targetsNetpol && hasWrite) {
          violations.push({
            rule: 'RB6003',
            severity: 'medium',
            message: `${role.kind}/${role.metadata.namespace ? role.metadata.namespace + '/' : ''}${role.metadata.name} can modify NetworkPolicies — can break pod network isolation`,
            resource: `${role.kind}/${role.metadata.namespace ? role.metadata.namespace + '/' : ''}${role.metadata.name}`,
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

export const RB6_RULES: Rule[] = [RB6001, RB6002, RB6003];
