import { describe, it, expect } from 'vitest';
import { hasViolation, makeClusterRole, makeRole, makeClusterBinding, makeBinding, makeServiceAccount, analyzeResources2 } from '../helpers';

describe('RB4001 - automountServiceAccountToken not false', () => {
  it('flags SA without automountServiceAccountToken: false', () => {
    const { violations } = analyzeResources2([
      makeServiceAccount('my-sa', 'default'),
    ]);
    expect(hasViolation(violations, 'RB4001')).toBe(true);
  });

  it('does not flag SA with automountServiceAccountToken: false', () => {
    const { violations } = analyzeResources2([
      makeServiceAccount('my-sa', 'default', false),
    ]);
    expect(hasViolation(violations, 'RB4001')).toBe(false);
  });

  it('flags SA with automountServiceAccountToken: true', () => {
    const { violations } = analyzeResources2([
      makeServiceAccount('my-sa', 'default', true),
    ]);
    expect(hasViolation(violations, 'RB4001')).toBe(true);
  });
});

describe('RB4002 - default ServiceAccount in RoleBinding', () => {
  it('flags RoleBinding to default SA', () => {
    const binding = makeBinding('default', 'pod-reader', 'default');
    const role = makeRole('pod-reader', [{ apiGroups: [''], resources: ['pods'], verbs: ['get'] }]);
    const { violations } = analyzeResources2([binding, role]);
    expect(hasViolation(violations, 'RB4002')).toBe(true);
  });

  it('does not flag named SA in RoleBinding', () => {
    const binding = makeBinding('my-app-sa', 'pod-reader', 'default');
    const role = makeRole('pod-reader', [{ apiGroups: [''], resources: ['pods'], verbs: ['get'] }]);
    const { violations } = analyzeResources2([binding, role]);
    expect(hasViolation(violations, 'RB4002')).toBe(false);
  });
});

describe('RB4003 - SA bound to ClusterRole with broad permissions', () => {
  it('flags SA bound to ClusterRole with wildcard verbs', () => {
    const sa = makeServiceAccount('app-sa', 'default', false);
    const role = makeClusterRole('broad-role', [{ apiGroups: [''], resources: ['pods'], verbs: ['*'] }]);
    const binding = makeClusterBinding('app-sa', 'broad-role', 'default');
    const { violations } = analyzeResources2([sa, role, binding]);
    expect(hasViolation(violations, 'RB4003')).toBe(true);
  });

  it('does not flag SA bound to ClusterRole with specific permissions', () => {
    const sa = makeServiceAccount('safe-sa', 'default', false);
    const role = makeClusterRole('safe-role', [{ apiGroups: [''], resources: ['pods'], verbs: ['get'] }]);
    const binding = makeClusterBinding('safe-sa', 'safe-role', 'default');
    const { violations } = analyzeResources2([sa, role, binding]);
    expect(hasViolation(violations, 'RB4003')).toBe(false);
  });
});

describe('RB4004 - SA without namespace', () => {
  it('flags SA without namespace', () => {
    const sa = makeServiceAccount('no-ns-sa');
    sa.metadata.namespace = undefined;
    const { violations } = analyzeResources2([sa]);
    expect(hasViolation(violations, 'RB4004')).toBe(true);
  });

  it('does not flag SA with namespace', () => {
    const { violations } = analyzeResources2([
      makeServiceAccount('ns-sa', 'production', false),
    ]);
    expect(hasViolation(violations, 'RB4004')).toBe(false);
  });
});

describe('RB4005 - SA with no associated Role', () => {
  it('flags SA not referenced by any binding', () => {
    const { violations } = analyzeResources2([
      makeServiceAccount('orphan-sa', 'default', false),
    ]);
    expect(hasViolation(violations, 'RB4005')).toBe(true);
  });

  it('does not flag SA referenced by a RoleBinding', () => {
    const sa = makeServiceAccount('used-sa', 'default', false);
    const role = makeRole('some-role', [{ apiGroups: [''], resources: ['pods'], verbs: ['get'] }]);
    const binding = makeBinding('used-sa', 'some-role', 'default');
    const { violations } = analyzeResources2([sa, role, binding]);
    expect(hasViolation(violations, 'RB4005')).toBe(false);
  });
});

describe('RB4006 - RoleBinding in multiple namespaces for same SA', () => {
  it('flags SA bound via RoleBindings in multiple namespaces', () => {
    const b1 = makeBinding('multi-sa', 'role-a', 'ns-a');
    const b1_copy = makeBinding('multi-sa', 'role-b', 'ns-b');
    b1_copy.metadata.name = 'multi-sa-binding-2';
    const roleA = makeRole('role-a', [{ apiGroups: [''], resources: ['pods'], verbs: ['get'] }], 'ns-a');
    const roleB = makeRole('role-b', [{ apiGroups: [''], resources: ['pods'], verbs: ['get'] }], 'ns-b');
    b1.subjects[0].namespace = 'default';
    b1_copy.subjects[0].namespace = 'default';
    const { violations } = analyzeResources2([b1, b1_copy, roleA, roleB]);
    expect(hasViolation(violations, 'RB4006')).toBe(true);
  });

  it('does not flag SA in one namespace', () => {
    const binding = makeBinding('single-sa', 'role', 'default');
    const role = makeRole('role', [{ apiGroups: [''], resources: ['pods'], verbs: ['get'] }]);
    const { violations } = analyzeResources2([binding, role]);
    expect(hasViolation(violations, 'RB4006')).toBe(false);
  });
});

describe('RB4007 - SA without description annotation', () => {
  it('flags SA without description annotation', () => {
    const { violations } = analyzeResources2([
      makeServiceAccount('undescribed-sa', 'default', false),
    ]);
    expect(hasViolation(violations, 'RB4007')).toBe(true);
  });

  it('does not flag SA with description annotation', () => {
    const sa = makeServiceAccount('described-sa', 'default', false);
    sa.metadata.annotations = { description: 'This SA is for the app' };
    const { violations } = analyzeResources2([sa]);
    expect(hasViolation(violations, 'RB4007')).toBe(false);
  });
});

describe('RB4008 - SA token projected without expiry', () => {
  it('flags SA with explicit automount=true and no expiry annotation', () => {
    const { violations } = analyzeResources2([
      makeServiceAccount('token-sa', 'default', true),
    ]);
    expect(hasViolation(violations, 'RB4008')).toBe(true);
  });

  it('does not flag SA with automount=false', () => {
    const { violations } = analyzeResources2([
      makeServiceAccount('safe-sa', 'default', false),
    ]);
    expect(hasViolation(violations, 'RB4008')).toBe(false);
  });
});

describe('RB4009 - SA can create pods', () => {
  it('fires when SA is bound to role that allows create on pods', () => {
    const sa = makeServiceAccount('pod-creator-sa', 'default', false);
    const role = makeRole('pod-creator-role', [{ apiGroups: [''], resources: ['pods'], verbs: ['create'] }]);
    const binding = makeBinding('pod-creator-sa', 'pod-creator-role', 'default');
    const { violations } = analyzeResources2([sa, role, binding]);
    expect(hasViolation(violations, 'RB4009')).toBe(true);
  });

  it('fires when SA is bound to ClusterRole that allows create on pods', () => {
    const sa = makeServiceAccount('pod-creator-sa', 'default', false);
    const role = makeClusterRole('pod-creator-clusterrole', [{ apiGroups: [''], resources: ['pods'], verbs: ['create'] }]);
    const binding = makeClusterBinding('pod-creator-sa', 'pod-creator-clusterrole', 'default');
    const { violations } = analyzeResources2([sa, role, binding]);
    expect(hasViolation(violations, 'RB4009')).toBe(true);
  });

  it('does not fire when SA can only read pods', () => {
    const sa = makeServiceAccount('pod-reader-sa', 'default', false);
    const role = makeRole('pod-reader-role', [{ apiGroups: [''], resources: ['pods'], verbs: ['get', 'list'] }]);
    const binding = makeBinding('pod-reader-sa', 'pod-reader-role', 'default');
    const { violations } = analyzeResources2([sa, role, binding]);
    expect(hasViolation(violations, 'RB4009')).toBe(false);
  });
});
