import { describe, it, expect } from 'vitest';
import { convertRole, convertClusterRole, convertRoleBinding, convertClusterRoleBinding, convertServiceAccount, CLUSTER_SOURCE } from '../../src/cluster/converter';
import type { V1Role, V1ClusterRole, V1RoleBinding, V1ClusterRoleBinding, V1ServiceAccount } from '@kubernetes/client-node';

describe('convertRole', () => {
  it('converts V1Role to internal Role', () => {
    const v1Role: V1Role = {
      metadata: { name: 'pod-reader', namespace: 'default' },
      rules: [{
        apiGroups: [''],
        resources: ['pods'],
        verbs: ['get', 'list'],
      }],
    };
    const role = convertRole(v1Role);
    expect(role.kind).toBe('Role');
    expect(role.metadata.name).toBe('pod-reader');
    expect(role.metadata.namespace).toBe('default');
    expect(role.rules).toHaveLength(1);
    expect(role.rules[0].verbs).toEqual(['get', 'list']);
    expect(role.sourceFile).toBe(CLUSTER_SOURCE);
    expect(role.sourceLine).toBe(0);
  });

  it('converts undefined apiGroups to empty array', () => {
    const v1Role: V1Role = {
      metadata: { name: 'test', namespace: 'default' },
      rules: [{ verbs: ['get'] }],
    };
    const role = convertRole(v1Role);
    expect(role.rules[0].apiGroups).toEqual([]);
    expect(role.rules[0].resources).toEqual([]);
  });

  it('converts undefined rules to empty array', () => {
    const v1Role: V1Role = {
      metadata: { name: 'empty', namespace: 'default' },
    };
    const role = convertRole(v1Role);
    expect(role.rules).toEqual([]);
  });

  it('preserves resourceNames', () => {
    const v1Role: V1Role = {
      metadata: { name: 'specific', namespace: 'default' },
      rules: [{
        apiGroups: [''],
        resources: ['configmaps'],
        verbs: ['get'],
        resourceNames: ['my-config'],
      }],
    };
    const role = convertRole(v1Role);
    expect(role.rules[0].resourceNames).toEqual(['my-config']);
  });
});

describe('convertClusterRole', () => {
  it('converts V1ClusterRole with kind ClusterRole', () => {
    const v1ClusterRole: V1ClusterRole = {
      metadata: { name: 'cluster-reader' },
      rules: [{
        apiGroups: [''],
        resources: ['nodes'],
        verbs: ['get'],
      }],
    };
    const role = convertClusterRole(v1ClusterRole);
    expect(role.kind).toBe('ClusterRole');
    expect(role.metadata.namespace).toBeUndefined();
    expect(role.sourceFile).toBe(CLUSTER_SOURCE);
  });

  it('converts annotations and labels', () => {
    const v1ClusterRole: V1ClusterRole = {
      metadata: {
        name: 'annotated',
        annotations: { 'description': 'Test role' },
        labels: { 'app': 'test' },
      },
    };
    const role = convertClusterRole(v1ClusterRole);
    expect(role.metadata.annotations?.['description']).toBe('Test role');
    expect(role.metadata.labels?.['app']).toBe('test');
  });
});

describe('convertRoleBinding', () => {
  it('converts V1RoleBinding to internal RoleBinding', () => {
    const v1Binding: V1RoleBinding = {
      metadata: { name: 'test-binding', namespace: 'default' },
      subjects: [{
        kind: 'ServiceAccount',
        name: 'my-sa',
        namespace: 'default',
      }],
      roleRef: {
        kind: 'Role',
        name: 'pod-reader',
        apiGroup: 'rbac.authorization.k8s.io',
      },
    };
    const binding = convertRoleBinding(v1Binding);
    expect(binding.kind).toBe('RoleBinding');
    expect(binding.subjects).toHaveLength(1);
    expect(binding.subjects[0].name).toBe('my-sa');
    expect(binding.roleRef.name).toBe('pod-reader');
    expect(binding.sourceFile).toBe(CLUSTER_SOURCE);
  });

  it('converts undefined subjects to empty array', () => {
    const v1Binding: V1RoleBinding = {
      metadata: { name: 'empty-binding', namespace: 'default' },
      subjects: undefined as any,
      roleRef: {
        kind: 'Role',
        name: 'some-role',
        apiGroup: 'rbac.authorization.k8s.io',
      },
    };
    const binding = convertRoleBinding(v1Binding);
    expect(binding.subjects).toEqual([]);
  });
});

describe('convertClusterRoleBinding', () => {
  it('converts V1ClusterRoleBinding', () => {
    const v1Binding: V1ClusterRoleBinding = {
      metadata: { name: 'admin-binding' },
      subjects: [{
        kind: 'ServiceAccount',
        name: 'admin-sa',
        namespace: 'kube-system',
      }],
      roleRef: {
        kind: 'ClusterRole',
        name: 'cluster-admin',
        apiGroup: 'rbac.authorization.k8s.io',
      },
    };
    const binding = convertClusterRoleBinding(v1Binding);
    expect(binding.kind).toBe('ClusterRoleBinding');
    expect(binding.metadata.namespace).toBeUndefined();
    expect(binding.roleRef.name).toBe('cluster-admin');
  });
});

describe('convertServiceAccount', () => {
  it('converts V1ServiceAccount', () => {
    const v1SA: V1ServiceAccount = {
      metadata: { name: 'my-sa', namespace: 'default' },
      automountServiceAccountToken: false,
    };
    const sa = convertServiceAccount(v1SA);
    expect(sa.kind).toBe('ServiceAccount');
    expect(sa.metadata.name).toBe('my-sa');
    expect(sa.automountServiceAccountToken).toBe(false);
    expect(sa.sourceFile).toBe(CLUSTER_SOURCE);
  });

  it('converts automountServiceAccountToken: true', () => {
    const v1SA: V1ServiceAccount = {
      metadata: { name: 'token-sa', namespace: 'default' },
      automountServiceAccountToken: true,
    };
    const sa = convertServiceAccount(v1SA);
    expect(sa.automountServiceAccountToken).toBe(true);
  });

  it('handles undefined automountServiceAccountToken', () => {
    const v1SA: V1ServiceAccount = {
      metadata: { name: 'default-sa', namespace: 'default' },
    };
    const sa = convertServiceAccount(v1SA);
    expect(sa.automountServiceAccountToken).toBeUndefined();
  });
});
