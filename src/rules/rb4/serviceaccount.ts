import type { Rule, RuleContext, Violation } from '../types';
import { hasWildcard, hasAnyVerb, resourceLabel, bindingLabel, makeRoleKey } from '../utils';
import type { ServiceAccount, RoleBinding } from '../../parser/types';

function saLabel(sa: ServiceAccount): string {
  const ns = sa.metadata.namespace || 'default';
  return `ServiceAccount/${ns}/${sa.metadata.name}`;
}

export const RB4001: Rule = {
  id: 'RB4001',
  severity: 'warning',
  description: '`automountServiceAccountToken` not set to `false`',
  cisId: 'CIS 5.1.6',
  check(ctx: RuleContext): Violation[] {
    const violations: Violation[] = [];
    for (const sa of ctx.graph.serviceAccounts.values()) {
      if (sa.automountServiceAccountToken !== false) {
        violations.push({
          rule: 'RB4001',
          severity: 'warning',
          message: `${saLabel(sa)} does not set automountServiceAccountToken: false — token is auto-mounted`,
          resource: saLabel(sa),
          file: sa.sourceFile,
          line: sa.sourceLine,
        });
      }
    }
    return violations;
  },
};

export const RB4002: Rule = {
  id: 'RB4002',
  severity: 'warning',
  description: 'ServiceAccount name is `default` used in RoleBinding',
  check(ctx: RuleContext): Violation[] {
    const violations: Violation[] = [];
    const allBindings = [...ctx.graph.roleBindings, ...ctx.graph.clusterRoleBindings];
    for (const b of allBindings) {
      const hasDefaultSA = b.subjects.some(s => s.kind === 'ServiceAccount' && s.name === 'default');
      if (hasDefaultSA) {
        violations.push({
          rule: 'RB4002',
          severity: 'warning',
          message: `${bindingLabel(b)} binds to the 'default' ServiceAccount — use a dedicated ServiceAccount`,
          resource: bindingLabel(b),
          file: b.sourceFile,
          line: b.sourceLine,
        });
      }
    }
    return violations;
  },
};

export const RB4003: Rule = {
  id: 'RB4003',
  severity: 'error',
  description: 'ServiceAccount bound to ClusterRole with broad permissions',
  check(ctx: RuleContext): Violation[] {
    const violations: Violation[] = [];
    for (const b of ctx.graph.clusterRoleBindings) {
      const hasSASubject = b.subjects.some(s => s.kind === 'ServiceAccount');
      if (!hasSASubject) continue;

      const role = ctx.graph.clusterRoles.get(b.roleRef.name);
      if (!role) continue;

      const isBroad = role.rules.some(rule =>
        hasWildcard(rule.verbs) || hasWildcard(rule.resources)
      );
      if (isBroad) {
        violations.push({
          rule: 'RB4003',
          severity: 'error',
          message: `${bindingLabel(b)} binds ServiceAccount to ClusterRole '${b.roleRef.name}' with broad permissions`,
          resource: bindingLabel(b),
          file: b.sourceFile,
          line: b.sourceLine,
        });
      }
    }
    return violations;
  },
};

export const RB4004: Rule = {
  id: 'RB4004',
  severity: 'warning',
  description: 'ServiceAccount without namespace scope',
  check(ctx: RuleContext): Violation[] {
    const violations: Violation[] = [];
    for (const sa of ctx.graph.serviceAccounts.values()) {
      if (!sa.metadata.namespace) {
        violations.push({
          rule: 'RB4004',
          severity: 'warning',
          message: `ServiceAccount/${sa.metadata.name} has no namespace defined — may be applied to unintended namespace`,
          resource: `ServiceAccount/${sa.metadata.name}`,
          file: sa.sourceFile,
          line: sa.sourceLine,
        });
      }
    }
    return violations;
  },
};

export const RB4005: Rule = {
  id: 'RB4005',
  severity: 'info',
  description: 'ServiceAccount with no associated Role/ClusterRole',
  check(ctx: RuleContext): Violation[] {
    const violations: Violation[] = [];
    const allBindings = [...ctx.graph.roleBindings, ...ctx.graph.clusterRoleBindings];

    for (const sa of ctx.graph.serviceAccounts.values()) {
      const ns = sa.metadata.namespace;
      const isReferenced = allBindings.some(b =>
        b.subjects.some(s =>
          s.kind === 'ServiceAccount' && s.name === sa.metadata.name &&
          (!ns || s.namespace === ns || b.kind === 'ClusterRoleBinding')
        )
      );
      if (!isReferenced) {
        violations.push({
          rule: 'RB4005',
          severity: 'info',
          message: `${saLabel(sa)} has no RoleBinding or ClusterRoleBinding referencing it`,
          resource: saLabel(sa),
          file: sa.sourceFile,
          line: sa.sourceLine,
        });
      }
    }
    return violations;
  },
};

export const RB4006: Rule = {
  id: 'RB4006',
  severity: 'warning',
  description: 'RoleBinding in multiple namespaces for same SA',
  check(ctx: RuleContext): Violation[] {
    const violations: Violation[] = [];
    // Track namespaces per SA
    const saNamespaces = new Map<string, Set<string>>();
    const saBindingFiles = new Map<string, { file: string; line: number }>();

    for (const b of ctx.graph.roleBindings) {
      for (const s of b.subjects) {
        if (s.kind === 'ServiceAccount') {
          const key = `${s.namespace || 'default'}/${s.name}`;
          const bindingNs = b.metadata.namespace || 'default';
          if (!saNamespaces.has(key)) {
            saNamespaces.set(key, new Set());
            saBindingFiles.set(key, { file: b.sourceFile, line: b.sourceLine });
          }
          saNamespaces.get(key)!.add(bindingNs);
        }
      }
    }

    for (const [saKey, namespaces] of saNamespaces) {
      if (namespaces.size > 1) {
        const loc = saBindingFiles.get(saKey)!;
        violations.push({
          rule: 'RB4006',
          severity: 'warning',
          message: `ServiceAccount '${saKey}' is bound via RoleBindings in ${namespaces.size} different namespaces: ${[...namespaces].join(', ')}`,
          resource: `ServiceAccount/${saKey}`,
          file: loc.file,
          line: loc.line,
        });
      }
    }
    return violations;
  },
};

export const RB4007: Rule = {
  id: 'RB4007',
  severity: 'info',
  description: 'ServiceAccount without description annotation',
  check(ctx: RuleContext): Violation[] {
    const violations: Violation[] = [];
    for (const sa of ctx.graph.serviceAccounts.values()) {
      const annotations = sa.metadata.annotations || {};
      const hasDesc = annotations['description'] || annotations['kubectl.kubernetes.io/description'];
      if (!hasDesc) {
        violations.push({
          rule: 'RB4007',
          severity: 'info',
          message: `${saLabel(sa)} has no description annotation`,
          resource: saLabel(sa),
          file: sa.sourceFile,
          line: sa.sourceLine,
        });
      }
    }
    return violations;
  },
};

export const RB4008: Rule = {
  id: 'RB4008',
  severity: 'warning',
  description: 'ServiceAccount token projected without expiry',
  check(ctx: RuleContext): Violation[] {
    // This rule would normally inspect Pod specs for projected service account tokens
    // In manifest mode, we flag SAs that have automountServiceAccountToken: true explicitly
    // and no token expiry annotations as a proxy check
    const violations: Violation[] = [];
    for (const sa of ctx.graph.serviceAccounts.values()) {
      if (sa.automountServiceAccountToken === true) {
        const annotations = sa.metadata.annotations || {};
        const hasExpiryHint = annotations['token-expiry'] || annotations['rbacvet/token-expiry'];
        if (!hasExpiryHint) {
          violations.push({
            rule: 'RB4008',
            severity: 'warning',
            message: `${saLabel(sa)} explicitly enables token auto-mounting without expiry annotation`,
            resource: saLabel(sa),
            file: sa.sourceFile,
            line: sa.sourceLine,
          });
        }
      }
    }
    return violations;
  },
};

export const RB4_RULES: Rule[] = [
  RB4001, RB4002, RB4003, RB4004, RB4005, RB4006, RB4007, RB4008,
];
