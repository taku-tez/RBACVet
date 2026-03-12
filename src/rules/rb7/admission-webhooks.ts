import type { Rule, RuleContext, Violation } from '../types';
import { hasAnyVerb, hasResource, resourceLabel, WRITE_VERBS } from '../utils';
import type { Role } from '../../parser/types';

function allRoles(ctx: RuleContext): Role[] {
  return [...ctx.graph.roles.values(), ...ctx.graph.clusterRoles.values()];
}

const WEBHOOK_RESOURCES = [
  'validatingwebhookconfigurations',
  'mutatingwebhookconfigurations',
];

export const RB7001: Rule = {
  id: 'RB7001',
  severity: 'high',
  description: 'Role grants write access to admission webhook configurations (can disable security controls)',
  cisId: 'CIS 5.1.3',
  check(ctx: RuleContext): Violation[] {
    const violations: Violation[] = [];
    for (const role of allRoles(ctx)) {
      for (const rule of role.rules) {
        const targetsWebhook =
          WEBHOOK_RESOURCES.some(r => hasResource(rule, r)) ||
          rule.resources.includes('*');
        const wrongApiGroup =
          rule.apiGroups.includes('admissionregistration.k8s.io') ||
          rule.apiGroups.includes('*');
        if (targetsWebhook && wrongApiGroup && hasAnyVerb(rule, WRITE_VERBS)) {
          const matched = WEBHOOK_RESOURCES.filter(r => hasResource(rule, r));
          const resourceNames = matched.length > 0 ? matched.join(', ') : 'webhook configurations';
          violations.push({
            rule: 'RB7001',
            severity: 'high',
            message: `${resourceLabel(role)} can modify ${resourceNames} — allows disabling or tampering with admission webhooks (OPA Gatekeeper, Kyverno, etc.)`,
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

export const RB7002: Rule = {
  id: 'RB7002',
  severity: 'high',
  description: 'Role grants write access to `runtimeclasses` — allows bypassing container sandboxing (gVisor, Kata Containers)',
  cisId: 'CIS 5.1.3',
  check(ctx: RuleContext): Violation[] {
    const violations: Violation[] = [];
    for (const role of allRoles(ctx)) {
      for (const rule of role.rules) {
        const nodeGroup =
          rule.apiGroups.includes('node.k8s.io') || rule.apiGroups.includes('*');
        const targetsRuntime =
          rule.resources.includes('runtimeclasses') || rule.resources.includes('*');
        if (nodeGroup && targetsRuntime && hasAnyVerb(rule, WRITE_VERBS)) {
          violations.push({
            rule: 'RB7002',
            severity: 'high',
            message: `${resourceLabel(role)} can write RuntimeClasses — allows switching container runtime to less-secure handlers (e.g., replacing gVisor/Kata with runc), bypassing sandbox isolation`,
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

export const RB7_RULES: Rule[] = [RB7001, RB7002];
