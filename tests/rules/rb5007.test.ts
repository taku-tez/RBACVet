import { describe, it, expect } from 'vitest';
import { hasViolation, analyzeResources2 } from '../helpers';
import type { RoleBinding } from '../../src/parser/types';

describe('RB5007 - RoleBinding to system:authenticated', () => {
  it('flags binding to system:authenticated group', () => {
    const binding: RoleBinding = {
      kind: 'ClusterRoleBinding',
      apiVersion: 'rbac.authorization.k8s.io/v1',
      metadata: { name: 'auth-binding' },
      subjects: [{ kind: 'Group', name: 'system:authenticated' }],
      roleRef: { kind: 'ClusterRole', name: 'some-role', apiGroup: 'rbac.authorization.k8s.io' },
      sourceFile: 'test.yaml',
      sourceLine: 1,
    };
    const { violations } = analyzeResources2([binding]);
    expect(hasViolation(violations, 'RB5007')).toBe(true);
  });

  it('flags RoleBinding (namespaced) to system:authenticated group', () => {
    const binding: RoleBinding = {
      kind: 'RoleBinding',
      apiVersion: 'rbac.authorization.k8s.io/v1',
      metadata: { name: 'auth-rb', namespace: 'default' },
      subjects: [{ kind: 'Group', name: 'system:authenticated' }],
      roleRef: { kind: 'Role', name: 'some-role', apiGroup: 'rbac.authorization.k8s.io' },
      sourceFile: 'test.yaml',
      sourceLine: 1,
    };
    const { violations } = analyzeResources2([binding]);
    expect(hasViolation(violations, 'RB5007')).toBe(true);
  });

  it('does not flag binding to specific user', () => {
    const binding: RoleBinding = {
      kind: 'ClusterRoleBinding',
      apiVersion: 'rbac.authorization.k8s.io/v1',
      metadata: { name: 'user-binding' },
      subjects: [{ kind: 'User', name: 'alice' }],
      roleRef: { kind: 'ClusterRole', name: 'some-role', apiGroup: 'rbac.authorization.k8s.io' },
      sourceFile: 'test.yaml',
      sourceLine: 1,
    };
    const { violations } = analyzeResources2([binding]);
    expect(hasViolation(violations, 'RB5007')).toBe(false);
  });

  it('does not flag binding to system:unauthenticated (different rule)', () => {
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
    expect(hasViolation(violations, 'RB5007')).toBe(false);
  });
});
