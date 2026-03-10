import { describe, it, expect } from 'vitest';
import { hasViolation, makeClusterRole, makeRole, makeClusterBinding, makeBinding, analyzeResources2 } from '../helpers';
import type { RoleBinding } from '../../src/parser/types';

describe('RB5001 - RoleBinding to system:unauthenticated', () => {
  it('flags binding to system:unauthenticated group', () => {
    const binding: RoleBinding = {
      kind: 'ClusterRoleBinding',
      apiVersion: 'rbac.authorization.k8s.io/v1',
      metadata: { name: 'unauth-binding' },
      subjects: [{ kind: 'Group', name: 'system:unauthenticated' }],
      roleRef: { kind: 'ClusterRole', name: 'some-role', apiGroup: 'rbac.authorization.k8s.io' },
      sourceFile: 'test.yaml',
      sourceLine: 1,
    };
    const { violations } = analyzeResources2([binding]);
    expect(hasViolation(violations, 'RB5001')).toBe(true);
  });

  it('does not flag binding to authenticated group', () => {
    const binding = makeClusterBinding('my-sa', 'some-role', 'default');
    const { violations } = analyzeResources2([binding]);
    expect(hasViolation(violations, 'RB5001')).toBe(false);
  });
});

describe('RB5002 - RoleBinding to system:anonymous', () => {
  it('flags binding to system:anonymous', () => {
    const binding: RoleBinding = {
      kind: 'ClusterRoleBinding',
      apiVersion: 'rbac.authorization.k8s.io/v1',
      metadata: { name: 'anon-binding' },
      subjects: [{ kind: 'User', name: 'system:anonymous' }],
      roleRef: { kind: 'ClusterRole', name: 'some-role', apiGroup: 'rbac.authorization.k8s.io' },
      sourceFile: 'test.yaml',
      sourceLine: 1,
    };
    const { violations } = analyzeResources2([binding]);
    expect(hasViolation(violations, 'RB5002')).toBe(true);
  });

  it('does not flag normal user binding', () => {
    const binding: RoleBinding = {
      kind: 'RoleBinding',
      apiVersion: 'rbac.authorization.k8s.io/v1',
      metadata: { name: 'user-binding', namespace: 'default' },
      subjects: [{ kind: 'User', name: 'alice' }],
      roleRef: { kind: 'Role', name: 'some-role', apiGroup: 'rbac.authorization.k8s.io' },
      sourceFile: 'test.yaml',
      sourceLine: 1,
    };
    const { violations } = analyzeResources2([binding]);
    expect(hasViolation(violations, 'RB5002')).toBe(false);
  });
});

describe('RB5003 - ClusterRoleBinding count exceeds threshold', () => {
  it('flags when more than 10 ClusterRoleBindings', () => {
    const bindings = Array.from({ length: 11 }, (_, i) => makeClusterBinding(`sa${i}`, 'some-role', 'default'));
    const { violations } = analyzeResources2(bindings);
    expect(hasViolation(violations, 'RB5003')).toBe(true);
  });

  it('does not flag with 10 or fewer ClusterRoleBindings', () => {
    const bindings = Array.from({ length: 5 }, (_, i) => makeClusterBinding(`sa${i}`, 'some-role', 'default'));
    const { violations } = analyzeResources2(bindings);
    expect(hasViolation(violations, 'RB5003')).toBe(false);
  });
});

describe('RB5004 - overlapping ClusterRole permissions', () => {
  it('flags ClusterRoles with high overlap', () => {
    const role1 = makeClusterRole('role-a', [
      { apiGroups: [''], resources: ['pods', 'services'], verbs: ['get', 'list'] },
    ]);
    const role2 = makeClusterRole('role-b', [
      { apiGroups: [''], resources: ['pods', 'services'], verbs: ['get', 'list'] },
    ]);
    const { violations } = analyzeResources2([role1, role2]);
    expect(hasViolation(violations, 'RB5004')).toBe(true);
  });

  it('does not flag ClusterRoles with minimal overlap', () => {
    const role1 = makeClusterRole('role-a', [
      { apiGroups: [''], resources: ['pods'], verbs: ['get'] },
    ]);
    const role2 = makeClusterRole('role-b', [
      { apiGroups: ['apps'], resources: ['deployments'], verbs: ['list'] },
    ]);
    const { violations } = analyzeResources2([role1, role2]);
    expect(hasViolation(violations, 'RB5004')).toBe(false);
  });
});

describe('RB5005 - unused Role', () => {
  it('flags Role not referenced by any RoleBinding', () => {
    const role = makeRole('orphan-role', [{ apiGroups: [''], resources: ['pods'], verbs: ['get'] }]);
    const { violations } = analyzeResources2([role]);
    expect(hasViolation(violations, 'RB5005')).toBe(true);
  });

  it('does not flag Role that is referenced', () => {
    const role = makeRole('used-role', [{ apiGroups: [''], resources: ['pods'], verbs: ['get'] }]);
    const binding = makeBinding('my-sa', 'used-role', 'default');
    const { violations } = analyzeResources2([role, binding]);
    expect(hasViolation(violations, 'RB5005')).toBe(false);
  });
});

describe('RB5006 - orphaned RoleBinding', () => {
  it('flags RoleBinding referencing non-existent Role', () => {
    const binding = makeBinding('my-sa', 'nonexistent-role', 'default');
    const { violations } = analyzeResources2([binding]);
    expect(hasViolation(violations, 'RB5006')).toBe(true);
  });

  it('does not flag RoleBinding with valid Role reference', () => {
    const role = makeRole('real-role', [{ apiGroups: [''], resources: ['pods'], verbs: ['get'] }]);
    const binding = makeBinding('my-sa', 'real-role', 'default');
    const { violations } = analyzeResources2([role, binding]);
    expect(hasViolation(violations, 'RB5006')).toBe(false);
  });
});
