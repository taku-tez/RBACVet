import * as fs from 'fs';
import * as path from 'path';
import { parseFile } from '../parser/parser';
import { ALL_RULES } from '../rules/index';
import { computeScores } from './scorer';
import type { K8sResource, Role, RoleBinding, ServiceAccount, AuthorizationPolicy, ParseError } from '../parser/types';
import type { Violation, ResourceGraph } from '../rules/types';
import type { RBACVetConfig } from './config';
import type { ServiceAccountScore } from './scorer';
import { makeRoleKey, makeSAKey } from '../rules/utils';

export interface AnalysisResult {
  violations: Violation[];
  scores: ServiceAccountScore[];
  graph: ResourceGraph;
  parseErrors: ParseError[];
}

function buildGraph(resources: K8sResource[]): ResourceGraph {
  const roles = new Map<string, Role>();
  const clusterRoles = new Map<string, Role>();
  const roleBindings: RoleBinding[] = [];
  const clusterRoleBindings: RoleBinding[] = [];
  const serviceAccounts = new Map<string, ServiceAccount>();
  const authorizationPolicies: AuthorizationPolicy[] = [];

  for (const r of resources) {
    switch (r.kind) {
      case 'Role':
        roles.set(makeRoleKey(r.metadata.name, r.metadata.namespace), r);
        break;
      case 'ClusterRole':
        clusterRoles.set(r.metadata.name, r);
        break;
      case 'RoleBinding':
        roleBindings.push(r);
        break;
      case 'ClusterRoleBinding':
        clusterRoleBindings.push(r);
        break;
      case 'ServiceAccount': {
        const ns = r.metadata.namespace || 'default';
        serviceAccounts.set(makeSAKey(r.metadata.name, ns), r);
        break;
      }
      case 'AuthorizationPolicy':
        authorizationPolicies.push(r);
        break;
    }
  }

  return { roles, clusterRoles, roleBindings, clusterRoleBindings, serviceAccounts, authorizationPolicies };
}

export function analyzeResources(resources: K8sResource[], config: RBACVetConfig): Omit<AnalysisResult, 'parseErrors'> {
  const graph = buildGraph(resources);
  const ctx = { graph, config };

  const rawViolations: Violation[] = [];
  for (const rule of ALL_RULES) {
    if (config.ignore.includes(rule.id)) continue;
    rawViolations.push(...rule.check(ctx));
  }

  // Apply severity overrides
  const violations = rawViolations.map(v => {
    const override = config.override[v.rule];
    return override ? { ...v, severity: override.severity } : v;
  });

  violations.sort((a, b) => {
    if (a.file !== b.file) return a.file.localeCompare(b.file);
    return a.line - b.line;
  });

  const scoring = computeScores(
    graph,
    violations,
    config.riskScoreThreshold,
    config.trustedClusterAdminBindings,
  );

  return { violations, scores: scoring.scores, graph };
}

export function analyzeFiles(files: string[], config: RBACVetConfig): AnalysisResult {
  const allResources: K8sResource[] = [];
  const allErrors: ParseError[] = [];

  for (const file of files) {
    const content = fs.readFileSync(file, 'utf-8');
    const result = parseFile(content, file);
    allResources.push(...result.resources);
    allErrors.push(...result.errors);
  }

  const { violations, scores, graph } = analyzeResources(allResources, config);
  return { violations, scores, graph, parseErrors: allErrors };
}

export function collectYamlFiles(dir: string): string[] {
  const results: string[] = [];
  const entries = fs.readdirSync(dir, { recursive: true, encoding: 'utf-8' }) as string[];
  for (const entry of entries) {
    if (entry.endsWith('.yaml') || entry.endsWith('.yml')) {
      results.push(path.join(dir, entry));
    }
  }
  return results;
}
