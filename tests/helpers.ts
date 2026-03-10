import { parseFile } from '../src/parser/parser';
import { analyzeResources } from '../src/engine/analyzer';
import type { Role, RoleBinding, ServiceAccount, AuthorizationPolicy, PolicyRule, K8sResource } from '../src/parser/types';
import type { Violation } from '../src/rules/types';
import type { RBACVetConfig } from '../src/engine/config';
import type { AnalysisResult } from '../src/engine/analyzer';

const DEFAULT_CONFIG: RBACVetConfig = {
  ignore: [],
  override: {},
  riskScoreThreshold: 60,
  trustedClusterAdminBindings: [],
};

export function analyzeYaml(yamlContent: string, config: Partial<RBACVetConfig> = {}): Omit<AnalysisResult, 'parseErrors'> {
  const result = parseFile(yamlContent, 'test.yaml');
  return analyzeResources(result.resources, { ...DEFAULT_CONFIG, ...config });
}

export function hasViolation(violations: Violation[], ruleId: string): boolean {
  return violations.some(v => v.rule === ruleId);
}

export function getViolations(violations: Violation[], ruleId: string): Violation[] {
  return violations.filter(v => v.rule === ruleId);
}

export function makeRole(name: string, rules: PolicyRule[], ns?: string): Role {
  return {
    kind: 'Role',
    apiVersion: 'rbac.authorization.k8s.io/v1',
    metadata: { name, namespace: ns || 'default' },
    rules,
    sourceFile: 'test.yaml',
    sourceLine: 1,
  };
}

export function makeClusterRole(name: string, rules: PolicyRule[]): Role {
  return {
    kind: 'ClusterRole',
    apiVersion: 'rbac.authorization.k8s.io/v1',
    metadata: { name },
    rules,
    sourceFile: 'test.yaml',
    sourceLine: 1,
  };
}

export function makeBinding(saName: string, roleName: string, ns?: string, roleKind: 'Role' | 'ClusterRole' = 'Role'): RoleBinding {
  return {
    kind: 'RoleBinding',
    apiVersion: 'rbac.authorization.k8s.io/v1',
    metadata: { name: `${saName}-binding`, namespace: ns || 'default' },
    subjects: [{ kind: 'ServiceAccount', name: saName, namespace: ns || 'default' }],
    roleRef: { kind: roleKind, name: roleName, apiGroup: 'rbac.authorization.k8s.io' },
    sourceFile: 'test.yaml',
    sourceLine: 10,
  };
}

export function makeClusterBinding(saName: string, roleName: string, ns?: string): RoleBinding {
  return {
    kind: 'ClusterRoleBinding',
    apiVersion: 'rbac.authorization.k8s.io/v1',
    metadata: { name: `${saName}-cluster-binding` },
    subjects: [{ kind: 'ServiceAccount', name: saName, namespace: ns || 'default' }],
    roleRef: { kind: 'ClusterRole', name: roleName, apiGroup: 'rbac.authorization.k8s.io' },
    sourceFile: 'test.yaml',
    sourceLine: 10,
  };
}

export function makeServiceAccount(name: string, ns?: string, automount?: boolean): ServiceAccount {
  return {
    kind: 'ServiceAccount',
    apiVersion: 'v1',
    metadata: { name, namespace: ns || 'default' },
    automountServiceAccountToken: automount,
    sourceFile: 'test.yaml',
    sourceLine: 20,
  };
}

export function makeAuthorizationPolicy(
  name: string,
  spec: AuthorizationPolicy['spec'],
  ns = 'default',
): AuthorizationPolicy {
  return {
    kind: 'AuthorizationPolicy',
    apiVersion: 'security.istio.io/v1beta1',
    metadata: { name, namespace: ns },
    spec,
    sourceFile: 'test.yaml',
    sourceLine: 1,
  };
}

export function analyzeResources2(resources: K8sResource[], config: Partial<RBACVetConfig> = {}) {
  return analyzeResources(resources, { ...DEFAULT_CONFIG, ...config });
}
