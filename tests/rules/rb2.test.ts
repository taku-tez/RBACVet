import { describe, it, expect } from 'vitest';
import { hasViolation, getViolations, makeClusterRole, makeRole, makeClusterBinding, makeBinding, makeServiceAccount, analyzeResources2 } from '../helpers';

describe('RB2001 - ClusterRoleBinding to cluster-admin', () => {
  it('flags ClusterRoleBinding to cluster-admin', () => {
    const { violations } = analyzeResources2([
      makeClusterBinding('my-sa', 'cluster-admin', 'default'),
      makeServiceAccount('my-sa', 'default', false),
    ]);
    expect(hasViolation(violations, 'RB2001')).toBe(true);
  });

  it('does not flag trusted cluster-admin bindings', () => {
    const binding = makeClusterBinding('my-sa', 'cluster-admin', 'default');
    binding.metadata.name = 'trusted-binding';
    const { violations } = analyzeResources2(
      [binding, makeServiceAccount('my-sa', 'default', false)],
      { trustedClusterAdminBindings: ['trusted-binding'] },
    );
    expect(hasViolation(violations, 'RB2001')).toBe(false);
  });
});

describe('RB2002 - escalate verb', () => {
  it('flags escalate verb', () => {
    const { violations } = analyzeResources2([
      makeClusterRole('escalator', [{ apiGroups: ['rbac.authorization.k8s.io'], resources: ['roles'], verbs: ['escalate'] }]),
    ]);
    expect(hasViolation(violations, 'RB2002')).toBe(true);
  });

  it('does not flag bind verb (different rule)', () => {
    const { violations } = analyzeResources2([
      makeRole('binder', [{ apiGroups: ['rbac.authorization.k8s.io'], resources: ['roles'], verbs: ['bind'] }]),
    ]);
    expect(hasViolation(violations, 'RB2002')).toBe(false);
  });
});

describe('RB2003 - bind verb', () => {
  it('flags bind verb', () => {
    const { violations } = analyzeResources2([
      makeClusterRole('role-binder', [{ apiGroups: ['rbac.authorization.k8s.io'], resources: ['roles'], verbs: ['bind'] }]),
    ]);
    expect(hasViolation(violations, 'RB2003')).toBe(true);
  });

  it('does not flag get verb', () => {
    const { violations } = analyzeResources2([
      makeRole('reader', [{ apiGroups: ['rbac.authorization.k8s.io'], resources: ['roles'], verbs: ['get'] }]),
    ]);
    expect(hasViolation(violations, 'RB2003')).toBe(false);
  });
});

describe('RB2004 - modify Role/ClusterRole', () => {
  it('flags write access to roles', () => {
    const { violations } = analyzeResources2([
      makeClusterRole('rbac-admin', [{ apiGroups: ['rbac.authorization.k8s.io'], resources: ['roles'], verbs: ['create', 'update'] }]),
    ]);
    expect(hasViolation(violations, 'RB2004')).toBe(true);
  });

  it('does not flag read access to roles', () => {
    const { violations } = analyzeResources2([
      makeRole('rbac-reader', [{ apiGroups: ['rbac.authorization.k8s.io'], resources: ['roles'], verbs: ['get', 'list'] }]),
    ]);
    expect(hasViolation(violations, 'RB2004')).toBe(false);
  });

  it('flags write access via wildcard resources', () => {
    const { violations } = analyzeResources2([
      makeClusterRole('wildcard-admin', [{ apiGroups: ['rbac.authorization.k8s.io'], resources: ['*'], verbs: ['create'] }]),
    ]);
    expect(hasViolation(violations, 'RB2004')).toBe(true);
  });
});

describe('RB2005 - modify RoleBinding/ClusterRoleBinding', () => {
  it('flags write access to rolebindings', () => {
    const { violations } = analyzeResources2([
      makeClusterRole('binding-admin', [{ apiGroups: ['rbac.authorization.k8s.io'], resources: ['rolebindings'], verbs: ['create'] }]),
    ]);
    expect(hasViolation(violations, 'RB2005')).toBe(true);
  });

  it('does not flag read of rolebindings', () => {
    const { violations } = analyzeResources2([
      makeRole('binding-reader', [{ apiGroups: ['rbac.authorization.k8s.io'], resources: ['rolebindings'], verbs: ['list'] }]),
    ]);
    expect(hasViolation(violations, 'RB2005')).toBe(false);
  });

  it('flags write access via wildcard resources', () => {
    const { violations } = analyzeResources2([
      makeClusterRole('wildcard-binding-admin', [{ apiGroups: ['rbac.authorization.k8s.io'], resources: ['*'], verbs: ['create'] }]),
    ]);
    expect(hasViolation(violations, 'RB2005')).toBe(true);
  });
});

describe('RB2006 - impersonation', () => {
  it('flags impersonate verb on users', () => {
    const { violations } = analyzeResources2([
      makeClusterRole('impersonator', [{ apiGroups: [''], resources: ['users'], verbs: ['impersonate'] }]),
    ]);
    expect(hasViolation(violations, 'RB2006')).toBe(true);
  });

  it('does not flag get on users', () => {
    const { violations } = analyzeResources2([
      makeClusterRole('user-reader', [{ apiGroups: [''], resources: ['users'], verbs: ['get'] }]),
    ]);
    expect(hasViolation(violations, 'RB2006')).toBe(false);
  });
});

describe('RB2007 - tokenreviews/subjectaccessreviews', () => {
  it('flags tokenreviews access', () => {
    const { violations } = analyzeResources2([
      makeClusterRole('auth-checker', [{ apiGroups: ['authentication.k8s.io'], resources: ['tokenreviews'], verbs: ['create'] }]),
    ]);
    expect(hasViolation(violations, 'RB2007')).toBe(true);
  });

  it('flags subjectaccessreviews access', () => {
    const { violations } = analyzeResources2([
      makeClusterRole('authz-checker', [{ apiGroups: ['authorization.k8s.io'], resources: ['subjectaccessreviews'], verbs: ['create'] }]),
    ]);
    expect(hasViolation(violations, 'RB2007')).toBe(true);
  });
});

// RB2008 and RB2009 removed — superseded by RB7001 (admission-webhooks.ts)

describe('RB2012 - CertificateSigningRequest approval', () => {
  it('flags update on certificatesigningrequests/approval', () => {
    const { violations } = analyzeResources2([
      makeClusterRole('csr-approver', [{
        apiGroups: ['certificates.k8s.io'],
        resources: ['certificatesigningrequests/approval'],
        verbs: ['update'],
      }]),
    ]);
    expect(hasViolation(violations, 'RB2012')).toBe(true);
  });

  it('flags patch on certificatesigningrequests/approval', () => {
    const { violations } = analyzeResources2([
      makeClusterRole('csr-patcher', [{
        apiGroups: ['certificates.k8s.io'],
        resources: ['certificatesigningrequests/approval'],
        verbs: ['patch'],
      }]),
    ]);
    expect(hasViolation(violations, 'RB2012')).toBe(true);
  });

  it('flags approve verb on signers', () => {
    const { violations } = analyzeResources2([
      makeClusterRole('signer', [{
        apiGroups: ['certificates.k8s.io'],
        resources: ['signers'],
        verbs: ['approve'],
      }]),
    ]);
    expect(hasViolation(violations, 'RB2012')).toBe(true);
  });

  it('flags wildcard apiGroup with csr/approval update', () => {
    const { violations } = analyzeResources2([
      makeClusterRole('wildcard-csr', [{
        apiGroups: ['*'],
        resources: ['certificatesigningrequests/approval'],
        verbs: ['update'],
      }]),
    ]);
    expect(hasViolation(violations, 'RB2012')).toBe(true);
  });

  it('does not flag read-only access to certificatesigningrequests', () => {
    const { violations } = analyzeResources2([
      makeClusterRole('csr-reader', [{
        apiGroups: ['certificates.k8s.io'],
        resources: ['certificatesigningrequests'],
        verbs: ['get', 'list'],
      }]),
    ]);
    expect(hasViolation(violations, 'RB2012')).toBe(false);
  });

  it('does not flag update on CSR with wrong apiGroup', () => {
    const { violations } = analyzeResources2([
      makeClusterRole('wrong-group', [{
        apiGroups: [''],
        resources: ['certificatesigningrequests/approval'],
        verbs: ['update'],
      }]),
    ]);
    expect(hasViolation(violations, 'RB2012')).toBe(false);
  });

  it('violation message mentions cluster-admin identity', () => {
    const { violations } = analyzeResources2([
      makeClusterRole('csr-approver', [{
        apiGroups: ['certificates.k8s.io'],
        resources: ['certificatesigningrequests/approval'],
        verbs: ['update'],
      }]),
    ]);
    const v = violations.find(v => v.rule === 'RB2012');
    expect(v?.message).toContain('cluster-admin');
  });
});

describe('RB2010 - privilege escalation chain', () => {
  it('flags SA directly bound to cluster-admin', () => {
    const { violations } = analyzeResources2([
      makeServiceAccount('admin-sa', 'default', false),
      makeClusterBinding('admin-sa', 'cluster-admin', 'default'),
    ]);
    expect(hasViolation(violations, 'RB2010')).toBe(true);
  });

  it('flags SA bound to cluster-admin-equivalent ClusterRole', () => {
    const { violations } = analyzeResources2([
      makeServiceAccount('power-sa', 'default', false),
      makeClusterRole('super-admin', [{ apiGroups: ['*'], resources: ['*'], verbs: ['*'] }]),
      makeClusterBinding('power-sa', 'super-admin', 'default'),
    ]);
    expect(hasViolation(violations, 'RB2010')).toBe(true);
  });

  it('does not flag SA with minimal permissions', () => {
    const { violations } = analyzeResources2([
      makeServiceAccount('safe-sa', 'default', false),
      makeRole('pod-reader', [{ apiGroups: [''], resources: ['pods'], verbs: ['get'] }]),
      makeBinding('safe-sa', 'pod-reader', 'default'),
    ]);
    expect(hasViolation(violations, 'RB2010')).toBe(false);
  });
});

describe('RB2011 - ValidatingAdmissionPolicies write access', () => {
  it('fires for role with validatingadmissionpolicies write access', () => {
    const { violations } = analyzeResources2([
      makeClusterRole('vap-admin', [{
        apiGroups: ['admissionregistration.k8s.io'],
        resources: ['validatingadmissionpolicies'],
        verbs: ['create', 'update'],
      }]),
    ]);
    expect(hasViolation(violations, 'RB2011')).toBe(true);
  });

  it('fires for role with validatingadmissionpolicybindings write access', () => {
    const { violations } = analyzeResources2([
      makeClusterRole('vapb-admin', [{
        apiGroups: ['admissionregistration.k8s.io'],
        resources: ['validatingadmissionpolicybindings'],
        verbs: ['patch'],
      }]),
    ]);
    expect(hasViolation(violations, 'RB2011')).toBe(true);
  });

  it('does not fire for read-only access', () => {
    const { violations } = analyzeResources2([
      makeClusterRole('vap-reader', [{
        apiGroups: ['admissionregistration.k8s.io'],
        resources: ['validatingadmissionpolicies'],
        verbs: ['get', 'list'],
      }]),
    ]);
    expect(hasViolation(violations, 'RB2011')).toBe(false);
  });
});
