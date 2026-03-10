import type {
  V1Role, V1ClusterRole, V1RoleBinding, V1ClusterRoleBinding, V1ServiceAccount,
  V1PolicyRule, RbacV1Subject, V1RoleRef,
} from '@kubernetes/client-node';
import type { Role, RoleBinding, ServiceAccount, PolicyRule, Subject, RoleRef } from '../parser/types';

export const CLUSTER_SOURCE = '<cluster>';

function convertPolicyRule(r: V1PolicyRule): PolicyRule {
  return {
    apiGroups: r.apiGroups ?? [],
    resources: r.resources ?? [],
    verbs: r.verbs ?? [],
    resourceNames: r.resourceNames,
  };
}

function convertSubject(s: RbacV1Subject): Subject {
  return {
    kind: s.kind as Subject['kind'],
    name: s.name,
    namespace: s.namespace,
  };
}

function convertRoleRef(r: V1RoleRef): RoleRef {
  return {
    kind: r.kind as RoleRef['kind'],
    name: r.name,
    apiGroup: r.apiGroup,
  };
}

export function convertRole(r: V1Role | V1ClusterRole): Role {
  const isCluster = !('metadata' in r && (r as V1Role).metadata?.namespace);
  return {
    kind: isCluster ? 'ClusterRole' : 'Role',
    apiVersion: 'rbac.authorization.k8s.io/v1',
    metadata: {
      name: r.metadata?.name ?? '',
      namespace: r.metadata?.namespace,
      annotations: r.metadata?.annotations as Record<string, string> | undefined,
      labels: r.metadata?.labels as Record<string, string> | undefined,
    },
    rules: (r.rules ?? []).map(convertPolicyRule),
    sourceFile: CLUSTER_SOURCE,
    sourceLine: 0,
  };
}

export function convertClusterRole(r: V1ClusterRole): Role {
  return {
    kind: 'ClusterRole',
    apiVersion: 'rbac.authorization.k8s.io/v1',
    metadata: {
      name: r.metadata?.name ?? '',
      namespace: undefined,
      annotations: r.metadata?.annotations as Record<string, string> | undefined,
      labels: r.metadata?.labels as Record<string, string> | undefined,
    },
    rules: (r.rules ?? []).map(convertPolicyRule),
    sourceFile: CLUSTER_SOURCE,
    sourceLine: 0,
  };
}

export function convertRoleBinding(b: V1RoleBinding): RoleBinding {
  return {
    kind: 'RoleBinding',
    apiVersion: 'rbac.authorization.k8s.io/v1',
    metadata: {
      name: b.metadata?.name ?? '',
      namespace: b.metadata?.namespace,
      annotations: b.metadata?.annotations as Record<string, string> | undefined,
      labels: b.metadata?.labels as Record<string, string> | undefined,
    },
    subjects: (b.subjects ?? []).map(convertSubject),
    roleRef: convertRoleRef(b.roleRef),
    sourceFile: CLUSTER_SOURCE,
    sourceLine: 0,
  };
}

export function convertClusterRoleBinding(b: V1ClusterRoleBinding): RoleBinding {
  return {
    kind: 'ClusterRoleBinding',
    apiVersion: 'rbac.authorization.k8s.io/v1',
    metadata: {
      name: b.metadata?.name ?? '',
      namespace: undefined,
      annotations: b.metadata?.annotations as Record<string, string> | undefined,
      labels: b.metadata?.labels as Record<string, string> | undefined,
    },
    subjects: (b.subjects ?? []).map(convertSubject),
    roleRef: convertRoleRef(b.roleRef),
    sourceFile: CLUSTER_SOURCE,
    sourceLine: 0,
  };
}

export function convertServiceAccount(sa: V1ServiceAccount): ServiceAccount {
  return {
    kind: 'ServiceAccount',
    apiVersion: 'v1',
    metadata: {
      name: sa.metadata?.name ?? '',
      namespace: sa.metadata?.namespace,
      annotations: sa.metadata?.annotations as Record<string, string> | undefined,
      labels: sa.metadata?.labels as Record<string, string> | undefined,
    },
    automountServiceAccountToken: sa.automountServiceAccountToken,
    sourceFile: CLUSTER_SOURCE,
    sourceLine: 0,
  };
}
