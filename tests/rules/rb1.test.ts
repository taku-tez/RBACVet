import { describe, it, expect } from 'vitest';
import { analyzeYaml, hasViolation, getViolations, makeClusterRole, makeRole, analyzeResources2 } from '../helpers';

describe('RB1001 - wildcard verbs', () => {
  it('flags wildcard verb *', () => {
    const yaml = `
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: admin-role
rules:
- apiGroups: [""]
  resources: ["pods"]
  verbs: ["*"]
`;
    const { violations } = analyzeYaml(yaml);
    expect(hasViolation(violations, 'RB1001')).toBe(true);
  });

  it('does not flag specific verbs', () => {
    const yaml = `
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: pod-reader
  namespace: default
rules:
- apiGroups: [""]
  resources: ["pods"]
  verbs: ["get", "list"]
`;
    const { violations } = analyzeYaml(yaml);
    expect(hasViolation(violations, 'RB1001')).toBe(false);
  });
});

describe('RB1002 - wildcard resources', () => {
  it('flags wildcard resource *', () => {
    const yaml = `
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: broad-role
rules:
- apiGroups: [""]
  resources: ["*"]
  verbs: ["get"]
`;
    const { violations } = analyzeYaml(yaml);
    expect(hasViolation(violations, 'RB1002')).toBe(true);
  });

  it('does not flag specific resources', () => {
    const yaml = `
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: specific-role
  namespace: default
rules:
- apiGroups: [""]
  resources: ["pods", "services"]
  verbs: ["get"]
`;
    const { violations } = analyzeYaml(yaml);
    expect(hasViolation(violations, 'RB1002')).toBe(false);
  });
});

describe('RB1003 - wildcard apiGroups', () => {
  it('flags wildcard apiGroup *', () => {
    const yaml = `
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: broad-role
rules:
- apiGroups: ["*"]
  resources: ["pods"]
  verbs: ["get"]
`;
    const { violations } = analyzeYaml(yaml);
    expect(hasViolation(violations, 'RB1003')).toBe(true);
  });

  it('does not flag empty string apiGroup (core)', () => {
    const yaml = `
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: core-role
  namespace: default
rules:
- apiGroups: [""]
  resources: ["pods"]
  verbs: ["get"]
`;
    const { violations } = analyzeYaml(yaml);
    expect(hasViolation(violations, 'RB1003')).toBe(false);
  });
});

describe('RB1004 - create + delete on same resource', () => {
  it('flags create + delete combination', () => {
    const { violations } = analyzeResources2([
      makeClusterRole('destroyer', [{
        apiGroups: [''],
        resources: ['pods'],
        verbs: ['create', 'delete'],
      }]),
    ]);
    expect(hasViolation(violations, 'RB1004')).toBe(true);
  });

  it('does not flag create alone', () => {
    const { violations } = analyzeResources2([
      makeRole('creator', [{ apiGroups: [''], resources: ['pods'], verbs: ['create'] }]),
    ]);
    expect(hasViolation(violations, 'RB1004')).toBe(false);
  });

  it('flags create in one rule and delete in another rule of the same role', () => {
    const { violations } = analyzeResources2([
      makeClusterRole('cross-rule-destroyer', [
        { apiGroups: [''], resources: ['pods'], verbs: ['create'] },
        { apiGroups: [''], resources: ['deployments'], verbs: ['delete'] },
      ]),
    ]);
    expect(hasViolation(violations, 'RB1004')).toBe(true);
  });
});

describe('RB1005 - update + patch on all resources', () => {
  it('flags update + patch with wildcard resources', () => {
    const { violations } = analyzeResources2([
      makeClusterRole('patcher', [{
        apiGroups: [''],
        resources: ['*'],
        verbs: ['update', 'patch'],
      }]),
    ]);
    expect(hasViolation(violations, 'RB1005')).toBe(true);
  });

  it('does not flag update alone (no patch)', () => {
    const { violations } = analyzeResources2([
      makeRole('pod-updater', [{ apiGroups: [''], resources: ['pods'], verbs: ['update'] }]),
    ]);
    expect(hasViolation(violations, 'RB1005')).toBe(false);
  });

  it('flags update in one rule and patch in another rule of the same role', () => {
    const { violations } = analyzeResources2([
      makeClusterRole('cross-rule-patcher', [
        { apiGroups: [''], resources: ['pods'], verbs: ['update'] },
        { apiGroups: ['apps'], resources: ['deployments'], verbs: ['patch'] },
      ]),
    ]);
    expect(hasViolation(violations, 'RB1005')).toBe(true);
  });
});

describe('RB1006 - ClusterRole write to all core resources', () => {
  it('flags ClusterRole with write to all resources', () => {
    const { violations } = analyzeResources2([
      makeClusterRole('write-all', [{
        apiGroups: [''],
        resources: ['*'],
        verbs: ['create', 'update'],
      }]),
    ]);
    expect(hasViolation(violations, 'RB1006')).toBe(true);
  });

  it('does not flag Role (not ClusterRole)', () => {
    const { violations } = analyzeResources2([
      makeRole('write-all', [{ apiGroups: [''], resources: ['*'], verbs: ['create'] }]),
    ]);
    expect(hasViolation(violations, 'RB1006')).toBe(false);
  });
});

describe('RB1007 - list on all resources', () => {
  it('flags list on *', () => {
    const { violations } = analyzeResources2([
      makeClusterRole('lister', [{ apiGroups: [''], resources: ['*'], verbs: ['list'] }]),
    ]);
    expect(hasViolation(violations, 'RB1007')).toBe(true);
  });

  it('does not flag list on specific resource', () => {
    const { violations } = analyzeResources2([
      makeRole('pod-lister', [{ apiGroups: [''], resources: ['pods'], verbs: ['list'] }]),
    ]);
    expect(hasViolation(violations, 'RB1007')).toBe(false);
  });
});

describe('RB1008 - watch on all resources', () => {
  it('flags watch on *', () => {
    const { violations } = analyzeResources2([
      makeClusterRole('watcher', [{ apiGroups: [''], resources: ['*'], verbs: ['watch'] }]),
    ]);
    expect(hasViolation(violations, 'RB1008')).toBe(true);
  });

  it('does not flag watch on specific resource', () => {
    const { violations } = analyzeResources2([
      makeRole('pod-watcher', [{ apiGroups: [''], resources: ['pods'], verbs: ['watch'] }]),
    ]);
    expect(hasViolation(violations, 'RB1008')).toBe(false);
  });
});

describe('RB1009 - wildcard verbs on nodes', () => {
  it('flags * verbs on nodes', () => {
    const { violations } = analyzeResources2([
      makeClusterRole('node-admin', [{ apiGroups: [''], resources: ['nodes'], verbs: ['*'] }]),
    ]);
    expect(hasViolation(violations, 'RB1009')).toBe(true);
  });

  it('does not flag specific verbs on nodes', () => {
    const { violations } = analyzeResources2([
      makeClusterRole('node-reader', [{ apiGroups: [''], resources: ['nodes'], verbs: ['get'] }]),
    ]);
    expect(hasViolation(violations, 'RB1009')).toBe(false);
  });
});

describe('RB1010 - wildcard verbs on namespaces', () => {
  it('flags * verbs on namespaces', () => {
    const { violations } = analyzeResources2([
      makeClusterRole('ns-admin', [{ apiGroups: [''], resources: ['namespaces'], verbs: ['*'] }]),
    ]);
    expect(hasViolation(violations, 'RB1010')).toBe(true);
  });

  it('does not flag get on namespaces', () => {
    const { violations } = analyzeResources2([
      makeClusterRole('ns-reader', [{ apiGroups: [''], resources: ['namespaces'], verbs: ['get'] }]),
    ]);
    expect(hasViolation(violations, 'RB1010')).toBe(false);
  });
});

describe('RB1011 - deletecollection verb', () => {
  it('flags deletecollection', () => {
    const { violations } = analyzeResources2([
      makeRole('bulk-deleter', [{ apiGroups: [''], resources: ['pods'], verbs: ['deletecollection'] }]),
    ]);
    expect(hasViolation(violations, 'RB1011')).toBe(true);
  });

  it('does not flag delete without deletecollection', () => {
    const { violations } = analyzeResources2([
      makeRole('deleter', [{ apiGroups: [''], resources: ['pods'], verbs: ['delete'] }]),
    ]);
    expect(hasViolation(violations, 'RB1011')).toBe(false);
  });
});

describe('RB1012 - more than 20 rules', () => {
  it('flags role with 21 rules', () => {
    const rules = Array.from({ length: 21 }, (_, i) => ({
      apiGroups: [''],
      resources: [`resource${i}`],
      verbs: ['get'],
    }));
    const { violations } = analyzeResources2([makeRole('giant-role', rules)]);
    const v = getViolations(violations, 'RB1012');
    expect(v).toHaveLength(1);
    expect(v[0].message).toContain('21');
  });

  it('does not flag role with exactly 20 rules', () => {
    const rules = Array.from({ length: 20 }, (_, i) => ({
      apiGroups: [''],
      resources: [`resource${i}`],
      verbs: ['get'],
    }));
    const { violations } = analyzeResources2([makeRole('normal-role', rules)]);
    expect(hasViolation(violations, 'RB1012')).toBe(false);
  });
});

describe('RB1014 - pods/ephemeralcontainers write access', () => {
  it('flags update on pods/ephemeralcontainers', () => {
    const { violations } = analyzeResources2([
      makeRole('ephemeral-updater', [{ apiGroups: [''], resources: ['pods/ephemeralcontainers'], verbs: ['update'] }]),
    ]);
    expect(hasViolation(violations, 'RB1014')).toBe(true);
  });

  it('flags patch on pods/ephemeralcontainers', () => {
    const { violations } = analyzeResources2([
      makeRole('ephemeral-patcher', [{ apiGroups: [''], resources: ['pods/ephemeralcontainers'], verbs: ['patch'] }]),
    ]);
    expect(hasViolation(violations, 'RB1014')).toBe(true);
  });

  it('flags wildcard verb on pods/ephemeralcontainers', () => {
    const { violations } = analyzeResources2([
      makeRole('ephemeral-all', [{ apiGroups: [''], resources: ['pods/ephemeralcontainers'], verbs: ['*'] }]),
    ]);
    expect(hasViolation(violations, 'RB1014')).toBe(true);
  });

  it('does not flag read-only access to pods/ephemeralcontainers', () => {
    const { violations } = analyzeResources2([
      makeRole('ephemeral-reader', [{ apiGroups: [''], resources: ['pods/ephemeralcontainers'], verbs: ['get'] }]),
    ]);
    expect(hasViolation(violations, 'RB1014')).toBe(false);
  });

  it('does not flag roles without ephemeralcontainers', () => {
    const { violations } = analyzeResources2([
      makeRole('pod-reader', [{ apiGroups: [''], resources: ['pods'], verbs: ['update'] }]),
    ]);
    expect(hasViolation(violations, 'RB1014')).toBe(false);
  });

  it('violation message mentions container injection', () => {
    const { violations } = analyzeResources2([
      makeRole('ephemeral-updater', [{ apiGroups: [''], resources: ['pods/ephemeralcontainers'], verbs: ['update'] }]),
    ]);
    const v = violations.find(v => v.rule === 'RB1014');
    expect(v?.message).toContain('ephemeral containers');
  });
});
