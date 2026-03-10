import { describe, it, expect } from 'vitest';
import { hasViolation, makeClusterRole, makeRole, analyzeResources2 } from '../helpers';

describe('RB1013 - write-only access anti-pattern', () => {
  it('flags role with only write verbs', () => {
    const role = makeRole('write-only', [
      { apiGroups: [''], resources: ['pods'], verbs: ['create', 'delete'] },
    ]);
    const { violations } = analyzeResources2([role]);
    expect(hasViolation(violations, 'RB1013')).toBe(true);
  });

  it('flags ClusterRole with only update/patch verbs', () => {
    const role = makeClusterRole('patch-only', [
      { apiGroups: ['apps'], resources: ['deployments'], verbs: ['patch', 'update'] },
    ]);
    const { violations } = analyzeResources2([role]);
    expect(hasViolation(violations, 'RB1013')).toBe(true);
  });

  it('does not flag role with both read and write verbs', () => {
    const role = makeRole('read-write', [
      { apiGroups: [''], resources: ['pods'], verbs: ['get', 'create', 'delete'] },
    ]);
    const { violations } = analyzeResources2([role]);
    expect(hasViolation(violations, 'RB1013')).toBe(false);
  });

  it('does not flag read-only role', () => {
    const role = makeRole('read-only', [
      { apiGroups: [''], resources: ['pods'], verbs: ['get', 'list', 'watch'] },
    ]);
    const { violations } = analyzeResources2([role]);
    expect(hasViolation(violations, 'RB1013')).toBe(false);
  });

  it('does not flag role with wildcard verbs (covered by RB1001)', () => {
    const role = makeRole('wildcard', [
      { apiGroups: [''], resources: ['pods'], verbs: ['*'] },
    ]);
    const { violations } = analyzeResources2([role]);
    expect(hasViolation(violations, 'RB1013')).toBe(false);
  });
});

describe('RB5004 - apiGroup-aware overlap detection', () => {
  it('does not flag roles with same resource:verb but different apiGroups', () => {
    const role1 = makeClusterRole('core-pods', [
      { apiGroups: [''], resources: ['pods'], verbs: ['get'] },
    ]);
    const role2 = makeClusterRole('apps-pods', [
      { apiGroups: ['apps'], resources: ['pods'], verbs: ['get'] },
    ]);
    const { violations } = analyzeResources2([role1, role2]);
    expect(hasViolation(violations, 'RB5004')).toBe(false);
  });

  it('flags roles with same apiGroup+resource+verb combination', () => {
    const role1 = makeClusterRole('role-x', [
      { apiGroups: ['apps'], resources: ['deployments'], verbs: ['get', 'list'] },
    ]);
    const role2 = makeClusterRole('role-y', [
      { apiGroups: ['apps'], resources: ['deployments'], verbs: ['get', 'list'] },
    ]);
    const { violations } = analyzeResources2([role1, role2]);
    expect(hasViolation(violations, 'RB5004')).toBe(true);
  });
});
