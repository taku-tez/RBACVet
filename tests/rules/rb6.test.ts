import { describe, it, expect } from 'vitest';
import { hasViolation, makeRole, makeBinding, makeClusterRole, analyzeResources2 } from '../helpers';
import type { RoleBinding } from '../../src/parser/types';

describe('RB6001 - cross-namespace RoleBinding subject', () => {
  it('flags RoleBinding with SA from different namespace', () => {
    const binding: RoleBinding = {
      kind: 'RoleBinding',
      apiVersion: 'rbac.authorization.k8s.io/v1',
      metadata: { name: 'cross-ns-binding', namespace: 'ns-a' },
      subjects: [{
        kind: 'ServiceAccount',
        name: 'my-sa',
        namespace: 'ns-b',
      }],
      roleRef: {
        kind: 'Role',
        name: 'some-role',
        apiGroup: 'rbac.authorization.k8s.io',
      },
      sourceFile: 'test.yaml',
      sourceLine: 1,
    };
    const role = makeRole('some-role', [{ apiGroups: [''], resources: ['pods'], verbs: ['get'] }], 'ns-a');
    const { violations } = analyzeResources2([binding, role]);
    expect(hasViolation(violations, 'RB6001')).toBe(true);
  });

  it('does not flag RoleBinding with SA from same namespace', () => {
    const binding: RoleBinding = {
      kind: 'RoleBinding',
      apiVersion: 'rbac.authorization.k8s.io/v1',
      metadata: { name: 'same-ns-binding', namespace: 'default' },
      subjects: [{
        kind: 'ServiceAccount',
        name: 'my-sa',
        namespace: 'default',
      }],
      roleRef: {
        kind: 'Role',
        name: 'some-role',
        apiGroup: 'rbac.authorization.k8s.io',
      },
      sourceFile: 'test.yaml',
      sourceLine: 1,
    };
    const role = makeRole('some-role', [{ apiGroups: [''], resources: ['pods'], verbs: ['get'] }]);
    const { violations } = analyzeResources2([binding, role]);
    expect(hasViolation(violations, 'RB6001')).toBe(false);
  });

  it('does not flag RoleBinding with User subject from different namespace', () => {
    // User subjects don't have a namespace concept in the same way
    const binding: RoleBinding = {
      kind: 'RoleBinding',
      apiVersion: 'rbac.authorization.k8s.io/v1',
      metadata: { name: 'user-binding', namespace: 'ns-a' },
      subjects: [{
        kind: 'User',
        name: 'alice',
      }],
      roleRef: {
        kind: 'Role',
        name: 'some-role',
        apiGroup: 'rbac.authorization.k8s.io',
      },
      sourceFile: 'test.yaml',
      sourceLine: 1,
    };
    const role = makeRole('some-role', [{ apiGroups: [''], resources: ['pods'], verbs: ['get'] }], 'ns-a');
    const { violations } = analyzeResources2([binding, role]);
    expect(hasViolation(violations, 'RB6001')).toBe(false);
  });

describe('RB6002 - system:masters binding', () => {
  it('flags binding to system:masters group', () => {
    const binding: RoleBinding = {
      kind: 'ClusterRoleBinding',
      apiVersion: 'rbac.authorization.k8s.io/v1',
      metadata: { name: 'masters-binding' },
      subjects: [{ kind: 'Group', name: 'system:masters' }],
      roleRef: { kind: 'ClusterRole', name: 'some-role', apiGroup: 'rbac.authorization.k8s.io' },
      sourceFile: 'test.yaml',
      sourceLine: 1,
    };
    const { violations } = analyzeResources2([binding]);
    expect(hasViolation(violations, 'RB6002')).toBe(true);
  });

  it('does not flag binding to a normal group', () => {
    const binding: RoleBinding = {
      kind: 'ClusterRoleBinding',
      apiVersion: 'rbac.authorization.k8s.io/v1',
      metadata: { name: 'normal-binding' },
      subjects: [{ kind: 'Group', name: 'devs' }],
      roleRef: { kind: 'ClusterRole', name: 'some-role', apiGroup: 'rbac.authorization.k8s.io' },
      sourceFile: 'test.yaml',
      sourceLine: 1,
    };
    const { violations } = analyzeResources2([binding]);
    expect(hasViolation(violations, 'RB6002')).toBe(false);
  });
});

describe('RB6003 - networkpolicies write access', () => {
  it('flags role with write access to networkpolicies', () => {
    const role = makeClusterRole('netpol-writer', [
      { apiGroups: ['networking.k8s.io'], resources: ['networkpolicies'], verbs: ['create', 'delete'] },
    ]);
    const { violations } = analyzeResources2([role]);
    expect(hasViolation(violations, 'RB6003')).toBe(true);
  });

  it('does not flag role with read-only access to networkpolicies', () => {
    const role = makeClusterRole('netpol-reader', [
      { apiGroups: ['networking.k8s.io'], resources: ['networkpolicies'], verbs: ['get', 'list'] },
    ]);
    const { violations } = analyzeResources2([role]);
    expect(hasViolation(violations, 'RB6003')).toBe(false);
  });
});

  it('does not flag SA subject without explicit namespace', () => {
    const binding: RoleBinding = {
      kind: 'RoleBinding',
      apiVersion: 'rbac.authorization.k8s.io/v1',
      metadata: { name: 'no-ns-subject', namespace: 'default' },
      subjects: [{
        kind: 'ServiceAccount',
        name: 'my-sa',
        // no namespace set
      }],
      roleRef: {
        kind: 'Role',
        name: 'some-role',
        apiGroup: 'rbac.authorization.k8s.io',
      },
      sourceFile: 'test.yaml',
      sourceLine: 1,
    };
    const role = makeRole('some-role', [{ apiGroups: [''], resources: ['pods'], verbs: ['get'] }]);
    const { violations } = analyzeResources2([binding, role]);
    expect(hasViolation(violations, 'RB6001')).toBe(false);
  });
});
