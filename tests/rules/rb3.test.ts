import { describe, it, expect } from 'vitest';
import { hasViolation, makeClusterRole, makeRole, analyzeResources2 } from '../helpers';

describe('RB3001 - read access to secrets', () => {
  it('flags get on secrets', () => {
    const { violations } = analyzeResources2([
      makeRole('secret-reader', [{ apiGroups: [''], resources: ['secrets'], verbs: ['get'] }]),
    ]);
    expect(hasViolation(violations, 'RB3001')).toBe(true);
  });

  it('flags list on secrets', () => {
    const { violations } = analyzeResources2([
      makeRole('secret-lister', [{ apiGroups: [''], resources: ['secrets'], verbs: ['list'] }]),
    ]);
    expect(hasViolation(violations, 'RB3001')).toBe(true);
  });

  it('does not flag role without secret access', () => {
    const { violations } = analyzeResources2([
      makeRole('pod-reader', [{ apiGroups: [''], resources: ['pods'], verbs: ['get'] }]),
    ]);
    expect(hasViolation(violations, 'RB3001')).toBe(false);
  });
});

describe('RB3002 - write access to secrets', () => {
  it('flags create on secrets', () => {
    const { violations } = analyzeResources2([
      makeRole('secret-creator', [{ apiGroups: [''], resources: ['secrets'], verbs: ['create'] }]),
    ]);
    expect(hasViolation(violations, 'RB3002')).toBe(true);
  });

  it('flags delete on secrets', () => {
    const { violations } = analyzeResources2([
      makeRole('secret-deleter', [{ apiGroups: [''], resources: ['secrets'], verbs: ['delete'] }]),
    ]);
    expect(hasViolation(violations, 'RB3002')).toBe(true);
  });
});

describe('RB3003 - write access to configmaps', () => {
  it('flags create on configmaps', () => {
    const { violations } = analyzeResources2([
      makeRole('cm-creator', [{ apiGroups: [''], resources: ['configmaps'], verbs: ['create'] }]),
    ]);
    expect(hasViolation(violations, 'RB3003')).toBe(true);
  });

  it('does not flag read on configmaps', () => {
    const { violations } = analyzeResources2([
      makeRole('cm-reader', [{ apiGroups: [''], resources: ['configmaps'], verbs: ['get', 'list'] }]),
    ]);
    expect(hasViolation(violations, 'RB3003')).toBe(false);
  });
});

describe('RB3004 - pods/exec', () => {
  it('flags pods/exec access', () => {
    const { violations } = analyzeResources2([
      makeRole('exec-role', [{ apiGroups: [''], resources: ['pods/exec'], verbs: ['create'] }]),
    ]);
    expect(hasViolation(violations, 'RB3004')).toBe(true);
  });

  it('does not flag pods access (without exec)', () => {
    const { violations } = analyzeResources2([
      makeRole('pod-role', [{ apiGroups: [''], resources: ['pods'], verbs: ['get'] }]),
    ]);
    expect(hasViolation(violations, 'RB3004')).toBe(false);
  });
});

describe('RB3005 - pods/attach', () => {
  it('flags pods/attach access', () => {
    const { violations } = analyzeResources2([
      makeRole('attach-role', [{ apiGroups: [''], resources: ['pods/attach'], verbs: ['create'] }]),
    ]);
    expect(hasViolation(violations, 'RB3005')).toBe(true);
  });

  it('does not flag pods alone', () => {
    const { violations } = analyzeResources2([
      makeRole('pod-role', [{ apiGroups: [''], resources: ['pods'], verbs: ['create'] }]),
    ]);
    expect(hasViolation(violations, 'RB3005')).toBe(false);
  });
});

describe('RB3006 - pods/log', () => {
  it('flags pods/log access', () => {
    const { violations } = analyzeResources2([
      makeRole('log-role', [{ apiGroups: [''], resources: ['pods/log'], verbs: ['get'] }]),
    ]);
    expect(hasViolation(violations, 'RB3006')).toBe(true);
  });

  it('does not flag pods logs without subresource', () => {
    const { violations } = analyzeResources2([
      makeRole('pod-role', [{ apiGroups: [''], resources: ['pods'], verbs: ['get'] }]),
    ]);
    expect(hasViolation(violations, 'RB3006')).toBe(false);
  });
});

describe('RB3007 - etcd access', () => {
  it('flags etcd resource', () => {
    const { violations } = analyzeResources2([
      makeClusterRole('etcd-reader', [{ apiGroups: ['etcd.database.coreos.com'], resources: ['etcd'], verbs: ['get'] }]),
    ]);
    expect(hasViolation(violations, 'RB3007')).toBe(true);
  });

  it('flags etcdclusters resource', () => {
    const { violations } = analyzeResources2([
      makeClusterRole('etcd-admin', [{ apiGroups: ['etcd.database.coreos.com'], resources: ['etcdclusters'], verbs: ['create'] }]),
    ]);
    expect(hasViolation(violations, 'RB3007')).toBe(true);
  });
});

describe('RB3008 - persistentvolumes', () => {
  it('flags get on persistentvolumes', () => {
    const { violations } = analyzeResources2([
      makeClusterRole('pv-reader', [{ apiGroups: [''], resources: ['persistentvolumes'], verbs: ['get'] }]),
    ]);
    expect(hasViolation(violations, 'RB3008')).toBe(true);
  });

  it('flags persistentvolumeclaims (now included)', () => {
    const { violations } = analyzeResources2([
      makeRole('pvc-reader', [{ apiGroups: [''], resources: ['persistentvolumeclaims'], verbs: ['get'] }]),
    ]);
    expect(hasViolation(violations, 'RB3008')).toBe(true);
  });

  it('flags write access to persistentvolumeclaims', () => {
    const { violations } = analyzeResources2([
      makeRole('pvc-writer', [{ apiGroups: [''], resources: ['persistentvolumeclaims'], verbs: ['create', 'delete'] }]),
    ]);
    expect(hasViolation(violations, 'RB3008')).toBe(true);
  });

  it('flags write access to volumeattachments', () => {
    const { violations } = analyzeResources2([
      makeClusterRole('va-writer', [{ apiGroups: ['storage.k8s.io'], resources: ['volumeattachments'], verbs: ['create'] }]),
    ]);
    expect(hasViolation(violations, 'RB3008')).toBe(true);
  });
});

describe('RB3009 - secrets via wildcard apiGroup', () => {
  it('fires for secrets access via wildcard apiGroup', () => {
    const { violations } = analyzeResources2([
      makeClusterRole('wildcard-secret-reader', [{ apiGroups: ['*'], resources: ['secrets'], verbs: ['get'] }]),
    ]);
    expect(hasViolation(violations, 'RB3009')).toBe(true);
  });

  it('fires for wildcard resources with wildcard apiGroup', () => {
    const { violations } = analyzeResources2([
      makeClusterRole('wildcard-all', [{ apiGroups: ['*'], resources: ['*'], verbs: ['get'] }]),
    ]);
    expect(hasViolation(violations, 'RB3009')).toBe(true);
  });

  it('does not fire for non-secret wildcard apiGroup access', () => {
    const { violations } = analyzeResources2([
      makeClusterRole('wildcard-pods', [{ apiGroups: ['*'], resources: ['pods'], verbs: ['get'] }]),
    ]);
    expect(hasViolation(violations, 'RB3009')).toBe(false);
  });

  it('does not fire when apiGroup is specific (not wildcard)', () => {
    const { violations } = analyzeResources2([
      makeRole('core-secret-reader', [{ apiGroups: [''], resources: ['secrets'], verbs: ['get'] }]),
    ]);
    expect(hasViolation(violations, 'RB3009')).toBe(false);
  });
});

describe('RB3011 - nodes/proxy access', () => {
  it('flags get on nodes/proxy', () => {
    const { violations } = analyzeResources2([
      makeClusterRole('node-proxy-reader', [{ apiGroups: [''], resources: ['nodes/proxy'], verbs: ['get'] }]),
    ]);
    expect(hasViolation(violations, 'RB3011')).toBe(true);
  });

  it('flags create on nodes/proxy', () => {
    const { violations } = analyzeResources2([
      makeClusterRole('node-proxy-creator', [{ apiGroups: [''], resources: ['nodes/proxy'], verbs: ['create'] }]),
    ]);
    expect(hasViolation(violations, 'RB3011')).toBe(true);
  });

  it('flags wildcard verb on nodes/proxy', () => {
    const { violations } = analyzeResources2([
      makeClusterRole('node-proxy-all', [{ apiGroups: [''], resources: ['nodes/proxy'], verbs: ['*'] }]),
    ]);
    expect(hasViolation(violations, 'RB3011')).toBe(true);
  });

  it('does not flag access to nodes (non-proxy subresource)', () => {
    const { violations } = analyzeResources2([
      makeClusterRole('node-reader', [{ apiGroups: [''], resources: ['nodes'], verbs: ['get', 'list'] }]),
    ]);
    expect(hasViolation(violations, 'RB3011')).toBe(false);
  });

  it('violation message mentions kubelet API', () => {
    const { violations } = analyzeResources2([
      makeClusterRole('node-proxy-reader', [{ apiGroups: [''], resources: ['nodes/proxy'], verbs: ['get'] }]),
    ]);
    const v = violations.find(v => v.rule === 'RB3011');
    expect(v?.message).toContain('kubelet');
  });
});

describe('RB3012 - pods/proxy and services/proxy access', () => {
  it('flags get on pods/proxy', () => {
    const { violations } = analyzeResources2([
      makeRole('pod-proxy', [{ apiGroups: [''], resources: ['pods/proxy'], verbs: ['get'] }]),
    ]);
    expect(hasViolation(violations, 'RB3012')).toBe(true);
  });

  it('flags get on services/proxy', () => {
    const { violations } = analyzeResources2([
      makeRole('svc-proxy', [{ apiGroups: [''], resources: ['services/proxy'], verbs: ['get'] }]),
    ]);
    expect(hasViolation(violations, 'RB3012')).toBe(true);
  });

  it('flags wildcard resource including proxy subresources', () => {
    const { violations } = analyzeResources2([
      makeClusterRole('wildcard-resources', [{ apiGroups: [''], resources: ['*'], verbs: ['get'] }]),
    ]);
    expect(hasViolation(violations, 'RB3012')).toBe(true);
  });

  it('does not flag access to pods without proxy subresource', () => {
    const { violations } = analyzeResources2([
      makeRole('pod-reader', [{ apiGroups: [''], resources: ['pods'], verbs: ['get', 'list'] }]),
    ]);
    expect(hasViolation(violations, 'RB3012')).toBe(false);
  });

  it('violation message mentions NetworkPolicies', () => {
    const { violations } = analyzeResources2([
      makeRole('pod-proxy', [{ apiGroups: [''], resources: ['pods/proxy'], verbs: ['get'] }]),
    ]);
    const v = violations.find(v => v.rule === 'RB3012');
    expect(v?.message).toContain('NetworkPolicies');
  });
});

describe('RB3010 - pods/portforward access', () => {
  it('flags create on pods/portforward', () => {
    const { violations } = analyzeResources2([
      makeRole('port-forwarder', [{ apiGroups: [''], resources: ['pods/portforward'], verbs: ['create'] }]),
    ]);
    expect(hasViolation(violations, 'RB3010')).toBe(true);
  });

  it('flags wildcard verb on pods/portforward', () => {
    const { violations } = analyzeResources2([
      makeRole('port-forwarder-all', [{ apiGroups: [''], resources: ['pods/portforward'], verbs: ['*'] }]),
    ]);
    expect(hasViolation(violations, 'RB3010')).toBe(true);
  });

  it('does not flag roles without portforward', () => {
    const { violations } = analyzeResources2([
      makeRole('pod-reader', [{ apiGroups: [''], resources: ['pods'], verbs: ['get', 'list'] }]),
    ]);
    expect(hasViolation(violations, 'RB3010')).toBe(false);
  });

  it('does not flag get on pods/portforward (portforward requires create)', () => {
    const { violations } = analyzeResources2([
      makeRole('portforward-getter', [{ apiGroups: [''], resources: ['pods/portforward'], verbs: ['get'] }]),
    ]);
    expect(hasViolation(violations, 'RB3010')).toBe(false);
  });

  it('violation message mentions NetworkPolicy bypass', () => {
    const { violations } = analyzeResources2([
      makeRole('port-forwarder', [{ apiGroups: [''], resources: ['pods/portforward'], verbs: ['create'] }]),
    ]);
    const v = violations.find(v => v.rule === 'RB3010');
    expect(v?.message).toContain('NetworkPolicies');
  });
});
