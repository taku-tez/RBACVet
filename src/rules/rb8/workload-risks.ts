import type { Rule, RuleContext, Violation } from '../types';
import { hasAnyVerb, hasResource, resourceLabel, WRITE_VERBS } from '../utils';
import type { Role } from '../../parser/types';

function allRoles(ctx: RuleContext): Role[] {
  return [...ctx.graph.roles.values(), ...ctx.graph.clusterRoles.values()];
}

export const RB8001: Rule = {
  id: 'RB8001',
  severity: 'medium',
  description: 'Role grants write access to `customresourcedefinitions` — can extend the Kubernetes API surface',
  check(ctx: RuleContext): Violation[] {
    const violations: Violation[] = [];
    for (const role of allRoles(ctx)) {
      for (const rule of role.rules) {
        const apiExtGroup =
          rule.apiGroups.includes('apiextensions.k8s.io') || rule.apiGroups.includes('*');
        const targetsCRD =
          rule.resources.includes('customresourcedefinitions') || rule.resources.includes('*');
        if (apiExtGroup && targetsCRD && hasAnyVerb(rule, WRITE_VERBS)) {
          violations.push({
            rule: 'RB8001',
            severity: 'medium',
            message: `${resourceLabel(role)} can write CustomResourceDefinitions — allows adding new API resources to the cluster, expanding the attack surface`,
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

export const RB8002: Rule = {
  id: 'RB8002',
  severity: 'high',
  description: 'Role grants write access to `daemonsets` — allows running arbitrary code on every node',
  check(ctx: RuleContext): Violation[] {
    const violations: Violation[] = [];
    for (const role of allRoles(ctx)) {
      for (const rule of role.rules) {
        const appsGroup =
          rule.apiGroups.includes('apps') || rule.apiGroups.includes('*');
        const targetsDaemonSet =
          rule.resources.includes('daemonsets') || rule.resources.includes('*');
        if (appsGroup && targetsDaemonSet && hasAnyVerb(rule, WRITE_VERBS)) {
          violations.push({
            rule: 'RB8002',
            severity: 'high',
            message: `${resourceLabel(role)} can write DaemonSets — allows scheduling arbitrary privileged containers on every node in the cluster`,
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

export const RB8003: Rule = {
  id: 'RB8003',
  severity: 'low',
  description: 'Role grants write access to `priorityclasses` — can preempt system-critical pods',
  check(ctx: RuleContext): Violation[] {
    const violations: Violation[] = [];
    for (const role of allRoles(ctx)) {
      for (const rule of role.rules) {
        const schedulingGroup =
          rule.apiGroups.includes('scheduling.k8s.io') || rule.apiGroups.includes('*');
        const targetsPriority =
          rule.resources.includes('priorityclasses') || rule.resources.includes('*');
        if (schedulingGroup && targetsPriority && hasAnyVerb(rule, WRITE_VERBS)) {
          violations.push({
            rule: 'RB8003',
            severity: 'low',
            message: `${resourceLabel(role)} can write PriorityClasses — allows creating high-priority classes that can evict system-critical pods`,
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

export const RB8004: Rule = {
  id: 'RB8004',
  severity: 'medium',
  description: 'Role grants write access to `jobs` or `cronjobs` — allows resource abuse or data exfiltration via batch workloads',
  check(ctx: RuleContext): Violation[] {
    const violations: Violation[] = [];
    const batchResources = ['jobs', 'cronjobs'];
    for (const role of allRoles(ctx)) {
      for (const rule of role.rules) {
        const batchGroup = rule.apiGroups.includes('batch') || rule.apiGroups.includes('*');
        const targetsBatch = batchResources.some(r => rule.resources.includes(r)) || rule.resources.includes('*');
        if (batchGroup && targetsBatch && hasAnyVerb(rule, WRITE_VERBS)) {
          const matched = batchResources.filter(r => rule.resources.includes(r));
          const res = matched.length > 0 ? matched.join('/') : 'batch resources';
          violations.push({
            rule: 'RB8004',
            severity: 'medium',
            message: `${resourceLabel(role)} can write ${res} — allows creating resource-intensive batch jobs or CronJobs for resource exhaustion or data exfiltration`,
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

export const RB8005: Rule = {
  id: 'RB8005',
  severity: 'medium',
  description: 'Role grants write access to `statefulsets` — allows creating persistent workloads with volume access',
  check(ctx: RuleContext): Violation[] {
    const violations: Violation[] = [];
    for (const role of allRoles(ctx)) {
      for (const rule of role.rules) {
        const appsGroup = rule.apiGroups.includes('apps') || rule.apiGroups.includes('*');
        const targetsStatefulSet = rule.resources.includes('statefulsets') || rule.resources.includes('*');
        if (appsGroup && targetsStatefulSet && hasAnyVerb(rule, WRITE_VERBS)) {
          violations.push({
            rule: 'RB8005',
            severity: 'medium',
            message: `${resourceLabel(role)} can write StatefulSets — allows creating persistent workloads with stable network identity and PersistentVolume access`,
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

export const RB8006: Rule = {
  id: 'RB8006',
  severity: 'low',
  description: 'Role grants write access to `horizontalpodautoscalers` — allows DoS via scale-to-zero or resource exhaustion',
  check(ctx: RuleContext): Violation[] {
    const violations: Violation[] = [];
    for (const role of allRoles(ctx)) {
      for (const rule of role.rules) {
        const autoscalingGroup = rule.apiGroups.includes('autoscaling') || rule.apiGroups.includes('*');
        const targetsHPA = rule.resources.includes('horizontalpodautoscalers') || rule.resources.includes('*');
        if (autoscalingGroup && targetsHPA && hasAnyVerb(rule, WRITE_VERBS)) {
          violations.push({
            rule: 'RB8006',
            severity: 'low',
            message: `${resourceLabel(role)} can write HorizontalPodAutoscalers — allows scaling workloads to zero (DoS) or to very large replicas (resource exhaustion)`,
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

export const RB8_RULES: Rule[] = [RB8001, RB8002, RB8003, RB8004, RB8005, RB8006];
