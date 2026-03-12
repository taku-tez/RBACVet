import { describe, it, expect } from 'vitest';
import { generateRuleFixes, RULE_FIX_MAP } from '../../src/fix/rule-fixes';
import { makeClusterRole, makeRole, makeServiceAccount, makeBinding, makeClusterBinding, analyzeResources2 } from '../helpers';
import type { Violation } from '../../src/rules/types';

function makeViolation(overrides: Partial<Violation> = {}): Violation {
  return {
    rule: 'RB1001',
    severity: 'error',
    message: 'test violation',
    resource: 'ClusterRole/test-role',
    file: 'test.yaml',
    line: 1,
    ...overrides,
  };
}

describe('RULE_FIX_MAP', () => {
  const expectedRules = [
    'RB1001', 'RB1002', 'RB1003', 'RB1004', 'RB1005', 'RB1006', 'RB1009', 'RB1010', 'RB1011', 'RB1014',
    'RB2001', 'RB2002', 'RB2003', 'RB2004', 'RB2005', 'RB2006', 'RB2007', 'RB2011', 'RB2012',
    'RB3001', 'RB3002', 'RB3003', 'RB3004', 'RB3005', 'RB3006', 'RB3007', 'RB3008', 'RB3009', 'RB3010', 'RB3011', 'RB3012',
    'RB4001', 'RB4002', 'RB4003', 'RB4004', 'RB4005', 'RB4006', 'RB4007', 'RB4008', 'RB4009',
    'RB5001', 'RB5002', 'RB5007', 'RB5008',
    'RB6001', 'RB6002',
    'RB7001', 'RB7002',
    'RB8001', 'RB8002', 'RB8003', 'RB8004', 'RB8005', 'RB8006',
    'RB9001', 'RB9002', 'RB9003', 'RB9004',
    'IS1001', 'IS1002', 'IS1003',
  ];

  it(`has entries for all ${expectedRules.length} rules`, () => {
    for (const id of expectedRules) {
      expect(RULE_FIX_MAP.has(id), `expected fix for ${id}`).toBe(true);
    }
  });

  it('has correct total count', () => {
    expect(RULE_FIX_MAP.size).toBe(expectedRules.length);
  });
});

describe('RB1001 fix - wildcard verbs', () => {
  it('replaces wildcard verbs with read-only verbs', () => {
    const role = makeClusterRole('test-role', [{
      apiGroups: [''],
      resources: ['pods'],
      verbs: ['*'],
    }]);
    const { graph } = analyzeResources2([role]);
    const violation = makeViolation({ rule: 'RB1001', resource: 'ClusterRole/test-role' });
    const fixFn = RULE_FIX_MAP.get('RB1001')!;
    const suggestion = fixFn(violation, graph, 'en');
    expect(suggestion).not.toBeNull();
    expect(suggestion!.yamlPatch).not.toContain('"*"');
    expect(suggestion!.yamlPatch).toContain('get');
    expect(suggestion!.source).toBe('rule-based');
  });

  it('marks RB1001 fix as auto-applicable', () => {
    const role = makeClusterRole('auto-role', [{ apiGroups: [''], resources: ['pods'], verbs: ['*'] }]);
    const { graph } = analyzeResources2([role]);
    const violation = makeViolation({ rule: 'RB1001', resource: 'ClusterRole/auto-role' });
    const fix = RULE_FIX_MAP.get('RB1001')!(violation, graph, 'en');
    expect(fix!.autoApplicable).toBe(true);
  });

  it('generates Japanese explanation when lang=ja', () => {
    const role = makeClusterRole('ja-role', [{ apiGroups: [''], resources: ['pods'], verbs: ['*'] }]);
    const { graph } = analyzeResources2([role]);
    const violation = makeViolation({ rule: 'RB1001', resource: 'ClusterRole/ja-role' });
    const fix = RULE_FIX_MAP.get('RB1001')!(violation, graph, 'ja');
    expect(fix!.explanation).toContain('ワイルドカード');
  });
});

describe('RB1002 fix - wildcard resources', () => {
  it('replaces wildcard resource with pods placeholder', () => {
    const role = makeClusterRole('broad-role', [{
      apiGroups: [''],
      resources: ['*'],
      verbs: ['get'],
    }]);
    const { graph } = analyzeResources2([role]);
    const violation = makeViolation({ rule: 'RB1002', resource: 'ClusterRole/broad-role' });
    const fix = RULE_FIX_MAP.get('RB1002')!(violation, graph, 'en');
    expect(fix!.yamlPatch).not.toContain('"*"');
    expect(fix!.yamlPatch).toContain('pods');
  });

  it('marks RB1002 fix as NOT auto-applicable', () => {
    const role = makeClusterRole('broad-role', [{ apiGroups: [''], resources: ['*'], verbs: ['get'] }]);
    const { graph } = analyzeResources2([role]);
    const violation = makeViolation({ rule: 'RB1002', resource: 'ClusterRole/broad-role' });
    const fix = RULE_FIX_MAP.get('RB1002')!(violation, graph, 'en');
    expect(fix!.autoApplicable).toBe(false);
  });
});

describe('RB2001 fix - cluster-admin binding', () => {
  it('generates replacement ClusterRole + ClusterRoleBinding YAML', () => {
    const { graph } = analyzeResources2([]);
    const violation = makeViolation({
      rule: 'RB2001',
      resource: 'ClusterRoleBinding/admin-binding',
      file: 'test.yaml',
      line: 1,
    });
    const fix = RULE_FIX_MAP.get('RB2001')!(violation, graph, 'en');
    expect(fix!.yamlPatch).toContain('ClusterRole');
    expect(fix!.yamlPatch).toContain('ClusterRoleBinding');
    expect(fix!.autoApplicable).toBe(false);
  });
});

describe('RB3001 fix - secrets read', () => {
  it('removes list/watch from secrets rules', () => {
    const role = makeRole('secret-reader', [{
      apiGroups: [''],
      resources: ['secrets'],
      verbs: ['get', 'list', 'watch'],
    }]);
    const { graph } = analyzeResources2([role]);
    const violation = makeViolation({
      rule: 'RB3001',
      resource: 'Role/default/secret-reader',
      file: 'test.yaml',
    });
    const fix = RULE_FIX_MAP.get('RB3001')!(violation, graph, 'en');
    expect(fix).not.toBeNull();
    expect(fix!.autoApplicable).toBe(false);
  });
});

describe('RB4001 fix - automount', () => {
  it('generates automountServiceAccountToken: false patch', () => {
    const sa = makeServiceAccount('my-sa', 'default');
    const { graph } = analyzeResources2([sa]);
    const violation = makeViolation({
      rule: 'RB4001',
      resource: 'ServiceAccount/default/my-sa',
      file: 'test.yaml',
    });
    const fix = RULE_FIX_MAP.get('RB4001')!(violation, graph, 'en');
    expect(fix!.yamlPatch).toBe('automountServiceAccountToken: false');
    expect(fix!.autoApplicable).toBe(true);
  });

  it('generates Japanese explanation', () => {
    const sa = makeServiceAccount('sa-ja', 'default');
    const { graph } = analyzeResources2([sa]);
    const violation = makeViolation({ rule: 'RB4001', resource: 'ServiceAccount/default/sa-ja' });
    const fix = RULE_FIX_MAP.get('RB4001')!(violation, graph, 'ja');
    expect(fix!.explanation).toContain('トークン');
  });
});

describe('IS1001 fix - AuthorizationPolicy ALLOW with no rules', () => {
  it('generates a yamlPatch with ALLOW and principals', () => {
    const { graph } = analyzeResources2([]);
    const violation = makeViolation({
      rule: 'IS1001',
      resource: 'AuthorizationPolicy/default/allow-all',
      file: 'test.yaml',
      line: 1,
    });
    const fix = RULE_FIX_MAP.get('IS1001')!(violation, graph, 'en');
    expect(fix).not.toBeNull();
    expect(fix!.yamlPatch).toContain('ALLOW');
    expect(fix!.yamlPatch).toContain('principals');
  });

  it('is NOT autoApplicable', () => {
    const { graph } = analyzeResources2([]);
    const violation = makeViolation({
      rule: 'IS1001',
      resource: 'AuthorizationPolicy/default/allow-all',
      file: 'test.yaml',
      line: 1,
    });
    const fix = RULE_FIX_MAP.get('IS1001')!(violation, graph, 'en');
    expect(fix!.autoApplicable).toBe(false);
  });

  it('generates Japanese explanation when lang=ja', () => {
    const { graph } = analyzeResources2([]);
    const violation = makeViolation({
      rule: 'IS1001',
      resource: 'AuthorizationPolicy/default/allow-all',
      file: 'test.yaml',
      line: 1,
    });
    const fix = RULE_FIX_MAP.get('IS1001')!(violation, graph, 'ja');
    expect(fix!.explanation).toContain('AuthorizationPolicy');
    expect(fix!.explanation).toContain('危険');
  });
});

describe('RB1003 fix - wildcard apiGroups', () => {
  it('replaces wildcard apiGroup with TODO placeholder', () => {
    const role = makeClusterRole('broad-api', [{ apiGroups: ['*'], resources: ['pods'], verbs: ['get'] }]);
    const { graph } = analyzeResources2([role]);
    const violation = makeViolation({ rule: 'RB1003', resource: 'ClusterRole/broad-api' });
    const fix = RULE_FIX_MAP.get('RB1003')!(violation, graph, 'en');
    expect(fix).not.toBeNull();
    expect(fix!.yamlPatch).toContain('TODO');
    expect(fix!.autoApplicable).toBe(false);
  });

  it('generates Japanese explanation', () => {
    const role = makeClusterRole('broad-api-ja', [{ apiGroups: ['*'], resources: ['pods'], verbs: ['get'] }]);
    const { graph } = analyzeResources2([role]);
    const violation = makeViolation({ rule: 'RB1003', resource: 'ClusterRole/broad-api-ja' });
    const fix = RULE_FIX_MAP.get('RB1003')!(violation, graph, 'ja');
    expect(fix!.explanation).toContain('ワイルドカード');
  });
});

describe('RB1014 fix - pods/ephemeralcontainers', () => {
  it('removes pods/ephemeralcontainers from resources', () => {
    const role = makeRole('ephemeral-writer', [{
      apiGroups: [''],
      resources: ['pods/ephemeralcontainers'],
      verbs: ['update'],
    }]);
    const { graph } = analyzeResources2([role]);
    const violation = makeViolation({ rule: 'RB1014', resource: 'Role/default/ephemeral-writer' });
    const fix = RULE_FIX_MAP.get('RB1014')!(violation, graph, 'en');
    expect(fix).not.toBeNull();
    expect(fix!.yamlPatch).not.toContain('ephemeralcontainers');
    expect(fix!.autoApplicable).toBe(true);
  });
});

describe('RB2002 fix - escalate verb', () => {
  it('removes escalate verb from rules', () => {
    const role = makeClusterRole('escalator', [{
      apiGroups: ['rbac.authorization.k8s.io'],
      resources: ['roles'],
      verbs: ['get', 'escalate'],
    }]);
    const { graph } = analyzeResources2([role]);
    const violation = makeViolation({ rule: 'RB2002', resource: 'ClusterRole/escalator' });
    const fix = RULE_FIX_MAP.get('RB2002')!(violation, graph, 'en');
    expect(fix!.yamlPatch).not.toContain('escalate');
    expect(fix!.yamlPatch).toContain('get');
    expect(fix!.autoApplicable).toBe(true);
  });
});

describe('RB2003 fix - bind verb', () => {
  it('removes bind verb, keeps other verbs', () => {
    const role = makeClusterRole('binder', [{
      apiGroups: ['rbac.authorization.k8s.io'],
      resources: ['roles'],
      verbs: ['get', 'list', 'bind'],
    }]);
    const { graph } = analyzeResources2([role]);
    const violation = makeViolation({ rule: 'RB2003', resource: 'ClusterRole/binder' });
    const fix = RULE_FIX_MAP.get('RB2003')!(violation, graph, 'en');
    expect(fix!.yamlPatch).not.toContain('bind');
    expect(fix!.yamlPatch).toContain('get');
    expect(fix!.autoApplicable).toBe(true);
  });
});

describe('RB2004 fix - RBAC role write', () => {
  it('restricts verbs to read-only', () => {
    const role = makeClusterRole('rbac-writer', [{
      apiGroups: ['rbac.authorization.k8s.io'],
      resources: ['roles'],
      verbs: ['get', 'list', 'create', 'update'],
    }]);
    const { graph } = analyzeResources2([role]);
    const violation = makeViolation({ rule: 'RB2004', resource: 'ClusterRole/rbac-writer' });
    const fix = RULE_FIX_MAP.get('RB2004')!(violation, graph, 'en');
    expect(fix!.yamlPatch).not.toContain('create');
    expect(fix!.yamlPatch).not.toContain('update');
    expect(fix!.autoApplicable).toBe(false);
  });
});

describe('RB2005 fix - RoleBinding write', () => {
  it('restricts binding write to read-only', () => {
    const role = makeClusterRole('binding-writer', [{
      apiGroups: ['rbac.authorization.k8s.io'],
      resources: ['rolebindings'],
      verbs: ['get', 'create', 'delete'],
    }]);
    const { graph } = analyzeResources2([role]);
    const violation = makeViolation({ rule: 'RB2005', resource: 'ClusterRole/binding-writer' });
    const fix = RULE_FIX_MAP.get('RB2005')!(violation, graph, 'en');
    expect(fix!.yamlPatch).not.toContain('create');
    expect(fix!.autoApplicable).toBe(false);
  });
});

describe('RB2006 fix - impersonate verb', () => {
  it('removes impersonate verb', () => {
    const role = makeClusterRole('impersonator', [{
      apiGroups: [''],
      resources: ['users'],
      verbs: ['impersonate'],
    }]);
    const { graph } = analyzeResources2([role]);
    const violation = makeViolation({ rule: 'RB2006', resource: 'ClusterRole/impersonator' });
    const fix = RULE_FIX_MAP.get('RB2006')!(violation, graph, 'en');
    expect(fix!.yamlPatch).not.toContain('impersonate');
    expect(fix!.autoApplicable).toBe(true);
  });
});

describe('RB2012 fix - CSR approval', () => {
  it('removes certificatesigningrequests/approval from resources', () => {
    const role = makeClusterRole('csr-approver', [{
      apiGroups: ['certificates.k8s.io'],
      resources: ['certificatesigningrequests/approval'],
      verbs: ['update'],
    }]);
    const { graph } = analyzeResources2([role]);
    const violation = makeViolation({ rule: 'RB2012', resource: 'ClusterRole/csr-approver' });
    const fix = RULE_FIX_MAP.get('RB2012')!(violation, graph, 'en');
    expect(fix!.yamlPatch).not.toContain('certificatesigningrequests/approval');
    expect(fix!.autoApplicable).toBe(false);
  });

  it('generates Japanese explanation', () => {
    const role = makeClusterRole('csr-ja', [{
      apiGroups: ['certificates.k8s.io'],
      resources: ['certificatesigningrequests/approval'],
      verbs: ['update'],
    }]);
    const { graph } = analyzeResources2([role]);
    const violation = makeViolation({ rule: 'RB2012', resource: 'ClusterRole/csr-ja' });
    const fix = RULE_FIX_MAP.get('RB2012')!(violation, graph, 'ja');
    expect(fix!.explanation).toContain('証明書');
  });
});

describe('RB3004 fix - pods/exec', () => {
  it('removes pods/exec resource and is auto-applicable', () => {
    const role = makeRole('exec-role', [{
      apiGroups: [''],
      resources: ['pods/exec'],
      verbs: ['create'],
    }]);
    const { graph } = analyzeResources2([role]);
    const violation = makeViolation({ rule: 'RB3004', resource: 'Role/default/exec-role' });
    const fix = RULE_FIX_MAP.get('RB3004')!(violation, graph, 'en');
    expect(fix!.yamlPatch).not.toContain('exec');
    expect(fix!.autoApplicable).toBe(true);
  });
});

describe('RB3005 fix - pods/attach', () => {
  it('removes pods/attach and is auto-applicable', () => {
    const role = makeRole('attach-role', [{
      apiGroups: [''],
      resources: ['pods/attach'],
      verbs: ['create'],
    }]);
    const { graph } = analyzeResources2([role]);
    const violation = makeViolation({ rule: 'RB3005', resource: 'Role/default/attach-role' });
    const fix = RULE_FIX_MAP.get('RB3005')!(violation, graph, 'en');
    expect(fix!.yamlPatch).not.toContain('attach');
    expect(fix!.autoApplicable).toBe(true);
  });
});

describe('RB3010 fix - pods/portforward', () => {
  it('removes pods/portforward and is auto-applicable', () => {
    const role = makeRole('pf-role', [{
      apiGroups: [''],
      resources: ['pods/portforward'],
      verbs: ['create'],
    }]);
    const { graph } = analyzeResources2([role]);
    const violation = makeViolation({ rule: 'RB3010', resource: 'Role/default/pf-role' });
    const fix = RULE_FIX_MAP.get('RB3010')!(violation, graph, 'en');
    expect(fix!.yamlPatch).not.toContain('portforward');
    expect(fix!.autoApplicable).toBe(true);
  });
});

describe('RB3011 fix - nodes/proxy', () => {
  it('removes nodes/proxy and is auto-applicable', () => {
    const role = makeClusterRole('node-proxy-role', [{
      apiGroups: [''],
      resources: ['nodes/proxy'],
      verbs: ['get'],
    }]);
    const { graph } = analyzeResources2([role]);
    const violation = makeViolation({ rule: 'RB3011', resource: 'ClusterRole/node-proxy-role' });
    const fix = RULE_FIX_MAP.get('RB3011')!(violation, graph, 'en');
    expect(fix!.yamlPatch).not.toContain('nodes/proxy');
    expect(fix!.autoApplicable).toBe(true);
  });

  it('mentions kubelet in explanation', () => {
    const role = makeClusterRole('node-proxy-role', [{
      apiGroups: [''],
      resources: ['nodes/proxy'],
      verbs: ['get'],
    }]);
    const { graph } = analyzeResources2([role]);
    const violation = makeViolation({ rule: 'RB3011', resource: 'ClusterRole/node-proxy-role' });
    const fix = RULE_FIX_MAP.get('RB3011')!(violation, graph, 'en');
    expect(fix!.explanation).toContain('kubelet');
  });
});

describe('RB4002 fix - default ServiceAccount', () => {
  it('generates dedicated ServiceAccount YAML', () => {
    const binding = makeBinding('default', 'some-role', 'default');
    const { graph } = analyzeResources2([binding]);
    const violation = makeViolation({
      rule: 'RB4002',
      resource: 'RoleBinding/default/default-binding',
      file: 'test.yaml',
    });
    const fix = RULE_FIX_MAP.get('RB4002')!(violation, graph, 'en');
    expect(fix!.yamlPatch).toContain('ServiceAccount');
    expect(fix!.autoApplicable).toBe(false);
  });

  it('generates Japanese explanation', () => {
    const { graph } = analyzeResources2([]);
    const violation = makeViolation({ rule: 'RB4002', resource: 'RoleBinding/default/default-binding' });
    const fix = RULE_FIX_MAP.get('RB4002')!(violation, graph, 'ja');
    expect(fix!.explanation).toContain('ServiceAccount');
  });
});

describe('RB5001 fix - system:unauthenticated binding', () => {
  it('generates patch removing unauthenticated subject', () => {
    const binding = makeClusterBinding('system:unauthenticated', 'some-role');
    binding.subjects = [
      { kind: 'Group', name: 'system:unauthenticated' },
      { kind: 'ServiceAccount', name: 'my-sa', namespace: 'default' },
    ];
    const { graph } = analyzeResources2([binding]);
    const violation = makeViolation({
      rule: 'RB5001',
      resource: `ClusterRoleBinding/${binding.metadata.name}`,
    });
    const fix = RULE_FIX_MAP.get('RB5001')!(violation, graph, 'en');
    expect(fix).not.toBeNull();
    expect(fix!.yamlPatch).not.toContain('system:unauthenticated');
    expect(fix!.autoApplicable).toBe(false);
  });
});

describe('RB6002 fix - system:masters binding', () => {
  it('generates replacement binding without system:masters', () => {
    const binding = makeClusterBinding('my-sa', 'cluster-admin');
    binding.subjects = [{ kind: 'Group', name: 'system:masters' }];
    const { graph } = analyzeResources2([binding]);
    const violation = makeViolation({
      rule: 'RB6002',
      resource: `ClusterRoleBinding/${binding.metadata.name}`,
    });
    const fix = RULE_FIX_MAP.get('RB6002')!(violation, graph, 'en');
    // The comment mentions system:masters but subjects should not include it
    expect(fix!.yamlPatch).toContain('cluster-admin');
    expect(fix!.yamlPatch).not.toContain('kind: Group\n  name: system:masters');
    expect(fix!.autoApplicable).toBe(false);
  });
});

describe('RB7001 fix - admission webhook write', () => {
  it('restricts webhook write to read-only', () => {
    const role = makeClusterRole('webhook-admin', [{
      apiGroups: ['admissionregistration.k8s.io'],
      resources: ['validatingwebhookconfigurations'],
      verbs: ['get', 'list', 'create', 'delete'],
    }]);
    const { graph } = analyzeResources2([role]);
    const violation = makeViolation({ rule: 'RB7001', resource: 'ClusterRole/webhook-admin' });
    const fix = RULE_FIX_MAP.get('RB7001')!(violation, graph, 'en');
    expect(fix!.yamlPatch).not.toContain('create');
    expect(fix!.yamlPatch).not.toContain('delete');
    expect(fix!.autoApplicable).toBe(false);
  });

  it('mentions OPA Gatekeeper in explanation', () => {
    const role = makeClusterRole('webhook-admin', [{
      apiGroups: ['admissionregistration.k8s.io'],
      resources: ['validatingwebhookconfigurations'],
      verbs: ['delete'],
    }]);
    const { graph } = analyzeResources2([role]);
    const violation = makeViolation({ rule: 'RB7001', resource: 'ClusterRole/webhook-admin' });
    const fix = RULE_FIX_MAP.get('RB7001')!(violation, graph, 'en');
    expect(fix!.explanation).toContain('OPA Gatekeeper');
  });
});

describe('RB3003 fix - configmaps write', () => {
  it('restricts configmap write verbs to read-only', () => {
    const role = makeRole('cm-writer', [{
      apiGroups: [''],
      resources: ['configmaps'],
      verbs: ['get', 'list', 'create', 'update'],
    }]);
    const { graph } = analyzeResources2([role]);
    const violation = makeViolation({ rule: 'RB3003', resource: 'Role/default/cm-writer' });
    const fix = RULE_FIX_MAP.get('RB3003')!(violation, graph, 'en');
    expect(fix!.yamlPatch).not.toContain('create');
    expect(fix!.yamlPatch).not.toContain('update');
    expect(fix!.yamlPatch).toContain('get');
    expect(fix!.autoApplicable).toBe(false);
  });

  it('generates Japanese explanation', () => {
    const role = makeRole('cm-writer', [{ apiGroups: [''], resources: ['configmaps'], verbs: ['create'] }]);
    const { graph } = analyzeResources2([role]);
    const fix = RULE_FIX_MAP.get('RB3003')!(makeViolation({ rule: 'RB3003', resource: 'Role/default/cm-writer' }), graph, 'ja');
    expect(fix!.explanation).toContain('ConfigMap');
  });
});

describe('RB3009 fix - secrets via wildcard apiGroup', () => {
  it('replaces wildcard apiGroup with core group for secret rules', () => {
    const role = makeClusterRole('wildcard-secrets', [{
      apiGroups: ['*'],
      resources: ['secrets'],
      verbs: ['get'],
    }]);
    const { graph } = analyzeResources2([role]);
    const violation = makeViolation({ rule: 'RB3009', resource: 'ClusterRole/wildcard-secrets' });
    const fix = RULE_FIX_MAP.get('RB3009')!(violation, graph, 'en');
    expect(fix!.yamlPatch).not.toContain('"*"');
    expect(fix!.autoApplicable).toBe(false);
  });
});

describe('RB3012 fix - pods/proxy and services/proxy', () => {
  it('removes proxy subresources and is auto-applicable', () => {
    const role = makeRole('proxy-role', [{
      apiGroups: [''],
      resources: ['pods/proxy', 'services/proxy'],
      verbs: ['get'],
    }]);
    const { graph } = analyzeResources2([role]);
    const violation = makeViolation({ rule: 'RB3012', resource: 'Role/default/proxy-role' });
    const fix = RULE_FIX_MAP.get('RB3012')!(violation, graph, 'en');
    expect(fix!.yamlPatch).not.toContain('pods/proxy');
    expect(fix!.yamlPatch).not.toContain('services/proxy');
    expect(fix!.autoApplicable).toBe(true);
  });
});

describe('RB5002 fix - system:anonymous binding', () => {
  it('removes system:anonymous from subjects', () => {
    const binding = makeClusterBinding('anon', 'some-role');
    binding.subjects = [
      { kind: 'User', name: 'system:anonymous' },
      { kind: 'ServiceAccount', name: 'my-sa', namespace: 'default' },
    ];
    const { graph } = analyzeResources2([binding]);
    const violation = makeViolation({ rule: 'RB5002', resource: `ClusterRoleBinding/${binding.metadata.name}` });
    const fix = RULE_FIX_MAP.get('RB5002')!(violation, graph, 'en');
    expect(fix!.yamlPatch).not.toContain('system:anonymous');
    expect(fix!.autoApplicable).toBe(false);
  });

  it('generates warning when all subjects would be removed', () => {
    const binding = makeClusterBinding('anon-only', 'some-role');
    binding.subjects = [{ kind: 'User', name: 'system:anonymous' }];
    const { graph } = analyzeResources2([binding]);
    const violation = makeViolation({ rule: 'RB5002', resource: `ClusterRoleBinding/${binding.metadata.name}` });
    const fix = RULE_FIX_MAP.get('RB5002')!(violation, graph, 'en');
    expect(fix!.yamlPatch).toContain('WARNING');
  });
});

describe('RB5007 fix - system:authenticated binding', () => {
  it('removes system:authenticated from subjects', () => {
    const binding = makeClusterBinding('all-authed', 'some-role');
    binding.subjects = [
      { kind: 'Group', name: 'system:authenticated' },
      { kind: 'ServiceAccount', name: 'my-sa', namespace: 'default' },
    ];
    const { graph } = analyzeResources2([binding]);
    const violation = makeViolation({ rule: 'RB5007', resource: `ClusterRoleBinding/${binding.metadata.name}` });
    const fix = RULE_FIX_MAP.get('RB5007')!(violation, graph, 'en');
    expect(fix!.yamlPatch).not.toContain('system:authenticated');
    expect(fix!.autoApplicable).toBe(false);
  });

  it('suggests specific subjects when all would be removed', () => {
    const binding = makeClusterBinding('auth-only', 'some-role');
    binding.subjects = [{ kind: 'Group', name: 'system:authenticated' }];
    const { graph } = analyzeResources2([binding]);
    const violation = makeViolation({ rule: 'RB5007', resource: `ClusterRoleBinding/${binding.metadata.name}` });
    const fix = RULE_FIX_MAP.get('RB5007')!(violation, graph, 'en');
    expect(fix!.yamlPatch).toContain('ServiceAccount');
  });
});

describe('RB5008 fix - leases write', () => {
  it('restricts lease write to read-only', () => {
    const role = makeClusterRole('lease-writer', [{
      apiGroups: ['coordination.k8s.io'],
      resources: ['leases'],
      verbs: ['get', 'list', 'create', 'update'],
    }]);
    const { graph } = analyzeResources2([role]);
    const violation = makeViolation({ rule: 'RB5008', resource: 'ClusterRole/lease-writer' });
    const fix = RULE_FIX_MAP.get('RB5008')!(violation, graph, 'en');
    expect(fix!.yamlPatch).not.toContain('create');
    expect(fix!.yamlPatch).not.toContain('update');
    expect(fix!.yamlPatch).toContain('get');
    expect(fix!.autoApplicable).toBe(false);
  });

  it('mentions leader election in explanation', () => {
    const role = makeClusterRole('lease-writer', [{ apiGroups: ['coordination.k8s.io'], resources: ['leases'], verbs: ['update'] }]);
    const { graph } = analyzeResources2([role]);
    const fix = RULE_FIX_MAP.get('RB5008')!(makeViolation({ rule: 'RB5008', resource: 'ClusterRole/lease-writer' }), graph, 'en');
    expect(fix!.explanation).toContain('leader election');
  });
});

describe('RB6001 fix - cross-namespace ServiceAccount', () => {
  it('generates ServiceAccount YAML for the binding namespace', () => {
    const binding = makeBinding('cross-sa', 'some-role', 'prod');
    binding.subjects = [{ kind: 'ServiceAccount', name: 'cross-sa', namespace: 'staging' }];
    const { graph } = analyzeResources2([binding]);
    const violation = makeViolation({ rule: 'RB6001', resource: 'RoleBinding/prod/cross-sa-binding' });
    const fix = RULE_FIX_MAP.get('RB6001')!(violation, graph, 'en');
    expect(fix!.yamlPatch).toContain('ServiceAccount');
    expect(fix!.autoApplicable).toBe(false);
  });
});

describe('RB8001 fix - CRD write', () => {
  it('restricts CRD write to read-only', () => {
    const role = makeClusterRole('crd-writer', [{
      apiGroups: ['apiextensions.k8s.io'],
      resources: ['customresourcedefinitions'],
      verbs: ['get', 'list', 'create', 'delete'],
    }]);
    const { graph } = analyzeResources2([role]);
    const violation = makeViolation({ rule: 'RB8001', resource: 'ClusterRole/crd-writer' });
    const fix = RULE_FIX_MAP.get('RB8001')!(violation, graph, 'en');
    expect(fix!.yamlPatch).not.toContain('create');
    expect(fix!.yamlPatch).not.toContain('delete');
    expect(fix!.autoApplicable).toBe(false);
  });
});

describe('RB8002 fix - daemonsets write', () => {
  it('restricts daemonset write to read-only', () => {
    const role = makeClusterRole('ds-writer', [{
      apiGroups: ['apps'],
      resources: ['daemonsets'],
      verbs: ['get', 'list', 'create', 'update'],
    }]);
    const { graph } = analyzeResources2([role]);
    const violation = makeViolation({ rule: 'RB8002', resource: 'ClusterRole/ds-writer' });
    const fix = RULE_FIX_MAP.get('RB8002')!(violation, graph, 'en');
    expect(fix!.yamlPatch).not.toContain('create');
    expect(fix!.yamlPatch).not.toContain('update');
    expect(fix!.autoApplicable).toBe(false);
  });

  it('mentions every node in explanation', () => {
    const role = makeClusterRole('ds-writer', [{ apiGroups: ['apps'], resources: ['daemonsets'], verbs: ['create'] }]);
    const { graph } = analyzeResources2([role]);
    const fix = RULE_FIX_MAP.get('RB8002')!(makeViolation({ rule: 'RB8002', resource: 'ClusterRole/ds-writer' }), graph, 'en');
    expect(fix!.explanation).toContain('every node');
  });
});

describe('RB8003 fix - priorityclasses write', () => {
  it('restricts priorityclass write to read-only', () => {
    const role = makeClusterRole('pc-writer', [{
      apiGroups: ['scheduling.k8s.io'],
      resources: ['priorityclasses'],
      verbs: ['get', 'list', 'create', 'update'],
    }]);
    const { graph } = analyzeResources2([role]);
    const violation = makeViolation({ rule: 'RB8003', resource: 'ClusterRole/pc-writer' });
    const fix = RULE_FIX_MAP.get('RB8003')!(violation, graph, 'en');
    expect(fix!.yamlPatch).not.toContain('create');
    expect(fix!.yamlPatch).not.toContain('update');
    expect(fix!.autoApplicable).toBe(false);
  });
});

describe('RB1004 fix - create+delete combined', () => {
  it('removes delete verb from rules', () => {
    const role = makeClusterRole('create-delete', [{ apiGroups: [''], resources: ['pods'], verbs: ['create', 'delete', 'get'] }]);
    const { graph } = analyzeResources2([role]);
    const fix = RULE_FIX_MAP.get('RB1004')!(makeViolation({ rule: 'RB1004', resource: 'ClusterRole/create-delete' }), graph, 'en');
    // The patch YAML should not contain 'delete' in the verbs list
    expect(fix!.yamlPatch).not.toContain('- delete');
    expect(fix!.yamlPatch).toContain('create');
    expect(fix!.autoApplicable).toBe(false);
  });
});

describe('RB1005 fix - update+patch combined', () => {
  it('removes patch verb', () => {
    const role = makeClusterRole('update-patch', [{ apiGroups: [''], resources: ['deployments'], verbs: ['update', 'patch', 'get'] }]);
    const { graph } = analyzeResources2([role]);
    const fix = RULE_FIX_MAP.get('RB1005')!(makeViolation({ rule: 'RB1005', resource: 'ClusterRole/update-patch' }), graph, 'en');
    expect(fix!.yamlPatch).not.toContain('patch');
    expect(fix!.yamlPatch).toContain('update');
    expect(fix!.autoApplicable).toBe(false);
  });
});

describe('RB1006 fix - ClusterRole all-core write', () => {
  it('restricts to read-only', () => {
    const role = makeClusterRole('all-core-writer', [{ apiGroups: [''], resources: ['*'], verbs: ['get', 'list', 'create', 'delete'] }]);
    const { graph } = analyzeResources2([role]);
    const fix = RULE_FIX_MAP.get('RB1006')!(makeViolation({ rule: 'RB1006', resource: 'ClusterRole/all-core-writer' }), graph, 'en');
    expect(fix!.yamlPatch).not.toContain('create');
    expect(fix!.yamlPatch).not.toContain('delete');
    expect(fix!.autoApplicable).toBe(false);
  });
});

describe('RB1009 fix - wildcard verbs on nodes', () => {
  it('restricts node verbs to read-only', () => {
    const role = makeClusterRole('node-all', [{ apiGroups: [''], resources: ['nodes'], verbs: ['*'] }]);
    const { graph } = analyzeResources2([role]);
    const fix = RULE_FIX_MAP.get('RB1009')!(makeViolation({ rule: 'RB1009', resource: 'ClusterRole/node-all' }), graph, 'en');
    expect(fix!.yamlPatch).not.toContain('"*"');
    expect(fix!.autoApplicable).toBe(false);
  });
});

describe('RB1010 fix - wildcard verbs on namespaces', () => {
  it('restricts namespace verbs to read-only', () => {
    const role = makeClusterRole('ns-all', [{ apiGroups: [''], resources: ['namespaces'], verbs: ['*'] }]);
    const { graph } = analyzeResources2([role]);
    const fix = RULE_FIX_MAP.get('RB1010')!(makeViolation({ rule: 'RB1010', resource: 'ClusterRole/ns-all' }), graph, 'en');
    expect(fix!.yamlPatch).not.toContain('"*"');
    expect(fix!.autoApplicable).toBe(false);
  });
});

describe('RB1011 fix - deletecollection verb', () => {
  it('removes deletecollection verb', () => {
    const role = makeClusterRole('bulk-deleter', [{ apiGroups: [''], resources: ['pods'], verbs: ['get', 'list', 'deletecollection'] }]);
    const { graph } = analyzeResources2([role]);
    const fix = RULE_FIX_MAP.get('RB1011')!(makeViolation({ rule: 'RB1011', resource: 'ClusterRole/bulk-deleter' }), graph, 'en');
    expect(fix!.yamlPatch).not.toContain('deletecollection');
    expect(fix!.yamlPatch).toContain('get');
    expect(fix!.autoApplicable).toBe(true);
  });
});

describe('RB2007 fix - tokenreviews/subjectaccessreviews', () => {
  it('restricts auth resources to read-only', () => {
    const role = makeClusterRole('auth-checker', [{ apiGroups: ['authentication.k8s.io'], resources: ['tokenreviews'], verbs: ['create', 'get'] }]);
    const { graph } = analyzeResources2([role]);
    const fix = RULE_FIX_MAP.get('RB2007')!(makeViolation({ rule: 'RB2007', resource: 'ClusterRole/auth-checker' }), graph, 'en');
    expect(fix!.yamlPatch).not.toContain('create');
    expect(fix!.autoApplicable).toBe(false);
  });
});

describe('RB2011 fix - ValidatingAdmissionPolicy write', () => {
  it('restricts VAP to read-only', () => {
    const role = makeClusterRole('vap-writer', [{ apiGroups: ['admissionregistration.k8s.io'], resources: ['validatingadmissionpolicies'], verbs: ['create', 'update', 'get'] }]);
    const { graph } = analyzeResources2([role]);
    const fix = RULE_FIX_MAP.get('RB2011')!(makeViolation({ rule: 'RB2011', resource: 'ClusterRole/vap-writer' }), graph, 'en');
    expect(fix!.yamlPatch).not.toContain('create');
    expect(fix!.yamlPatch).not.toContain('update');
    expect(fix!.autoApplicable).toBe(false);
  });
});

describe('RB3006 fix - pods/log', () => {
  it('removes pods/log from resources', () => {
    const role = makeClusterRole('log-reader', [{ apiGroups: [''], resources: ['pods', 'pods/log'], verbs: ['get'] }]);
    const { graph } = analyzeResources2([role]);
    const fix = RULE_FIX_MAP.get('RB3006')!(makeViolation({ rule: 'RB3006', resource: 'ClusterRole/log-reader' }), graph, 'en');
    expect(fix!.yamlPatch).not.toContain('pods/log');
    expect(fix!.autoApplicable).toBe(false);
  });
});

describe('RB3007 fix - etcd access', () => {
  it('removes etcd from resources', () => {
    const role = makeClusterRole('etcd-accessor', [{ apiGroups: ['etcd.database.coreos.com'], resources: ['etcd', 'pods'], verbs: ['get', 'list'] }]);
    const { graph } = analyzeResources2([role]);
    const fix = RULE_FIX_MAP.get('RB3007')!(makeViolation({ rule: 'RB3007', resource: 'ClusterRole/etcd-accessor' }), graph, 'en');
    expect(fix!.yamlPatch).not.toContain("- etcd\n");
    expect(fix!.autoApplicable).toBe(false);
  });
});

describe('RB3008 fix - persistentvolumes access', () => {
  it('restricts PV access to read-only', () => {
    const role = makeClusterRole('pv-writer', [{ apiGroups: [''], resources: ['persistentvolumes', 'persistentvolumeclaims'], verbs: ['get', 'list', 'create', 'delete'] }]);
    const { graph } = analyzeResources2([role]);
    const fix = RULE_FIX_MAP.get('RB3008')!(makeViolation({ rule: 'RB3008', resource: 'ClusterRole/pv-writer' }), graph, 'en');
    expect(fix!.yamlPatch).not.toContain('create');
    expect(fix!.yamlPatch).not.toContain('delete');
    expect(fix!.autoApplicable).toBe(false);
  });
});

describe('RB7002 fix - runtimeclasses write', () => {
  it('restricts runtimeclass write to read-only', () => {
    const role = makeClusterRole('rc-writer', [{ apiGroups: ['node.k8s.io'], resources: ['runtimeclasses'], verbs: ['create', 'update', 'get'] }]);
    const { graph } = analyzeResources2([role]);
    const fix = RULE_FIX_MAP.get('RB7002')!(makeViolation({ rule: 'RB7002', resource: 'ClusterRole/rc-writer' }), graph, 'en');
    expect(fix!.yamlPatch).not.toContain('create');
    expect(fix!.yamlPatch).not.toContain('update');
    expect(fix!.autoApplicable).toBe(false);
  });

  it('mentions sandbox isolation in explanation', () => {
    const role = makeClusterRole('rc-writer', [{ apiGroups: ['node.k8s.io'], resources: ['runtimeclasses'], verbs: ['create'] }]);
    const { graph } = analyzeResources2([role]);
    const fix = RULE_FIX_MAP.get('RB7002')!(makeViolation({ rule: 'RB7002', resource: 'ClusterRole/rc-writer' }), graph, 'en');
    expect(fix!.explanation).toContain('sandbox');
  });
});

describe('RB8004 fix - batch/jobs write', () => {
  it('restricts jobs write to read-only', () => {
    const role = makeClusterRole('job-creator', [{ apiGroups: ['batch'], resources: ['jobs'], verbs: ['create', 'update', 'get'] }]);
    const { graph } = analyzeResources2([role]);
    const fix = RULE_FIX_MAP.get('RB8004')!(makeViolation({ rule: 'RB8004', resource: 'ClusterRole/job-creator' }), graph, 'en');
    expect(fix!.yamlPatch).not.toContain('create');
    expect(fix!.autoApplicable).toBe(false);
  });
});

describe('RB8005 fix - statefulsets write', () => {
  it('restricts statefulset write to read-only', () => {
    const role = makeClusterRole('sts-writer', [{ apiGroups: ['apps'], resources: ['statefulsets'], verbs: ['create', 'patch', 'get'] }]);
    const { graph } = analyzeResources2([role]);
    const fix = RULE_FIX_MAP.get('RB8005')!(makeViolation({ rule: 'RB8005', resource: 'ClusterRole/sts-writer' }), graph, 'en');
    expect(fix!.yamlPatch).not.toContain('create');
    expect(fix!.yamlPatch).not.toContain('patch');
    expect(fix!.autoApplicable).toBe(false);
  });
});

describe('RB8006 fix - HPA write', () => {
  it('restricts HPA write to read-only', () => {
    const role = makeClusterRole('hpa-writer', [{ apiGroups: ['autoscaling'], resources: ['horizontalpodautoscalers'], verbs: ['update', 'patch', 'get'] }]);
    const { graph } = analyzeResources2([role]);
    const fix = RULE_FIX_MAP.get('RB8006')!(makeViolation({ rule: 'RB8006', resource: 'ClusterRole/hpa-writer' }), graph, 'en');
    expect(fix!.yamlPatch).not.toContain('update');
    expect(fix!.autoApplicable).toBe(false);
  });
});

describe('IS1002 fix - wildcard principal', () => {
  it('generates a specific principal YAML', () => {
    const { graph } = analyzeResources2([]);
    const fix = RULE_FIX_MAP.get('IS1002')!(
      makeViolation({ rule: 'IS1002', resource: 'AuthorizationPolicy/default/allow-all' }), graph, 'en'
    );
    expect(fix!.yamlPatch).toContain('principals');
    expect(fix!.autoApplicable).toBe(false);
  });
});

describe('IS1003 fix - wildcard HTTP method', () => {
  it('generates specific methods YAML', () => {
    const { graph } = analyzeResources2([]);
    const fix = RULE_FIX_MAP.get('IS1003')!(
      makeViolation({ rule: 'IS1003', resource: 'AuthorizationPolicy/default/allow-all' }), graph, 'en'
    );
    expect(fix!.yamlPatch).toContain('methods');
    expect(fix!.autoApplicable).toBe(false);
  });
});

describe('RB4003 fix - SA bound to broad ClusterRole', () => {
  it('generates restricted ClusterRole YAML when binding found', () => {
    const binding = makeClusterBinding('my-sa', 'cluster-admin');
    const { graph } = analyzeResources2([binding]);
    const violation = makeViolation({ rule: 'RB4003', resource: `ClusterRoleBinding/${binding.metadata.name}` });
    const fix = RULE_FIX_MAP.get('RB4003')!(violation, graph, 'en');
    expect(fix).not.toBeNull();
    expect(fix!.yamlPatch).toContain('ClusterRole');
    expect(fix!.autoApplicable).toBe(false);
  });

  it('returns null when binding not found', () => {
    const { graph } = analyzeResources2([]);
    const violation = makeViolation({ rule: 'RB4003', resource: 'ClusterRoleBinding/nonexistent' });
    const fix = RULE_FIX_MAP.get('RB4003')!(violation, graph, 'en');
    expect(fix).toBeNull();
  });
});

describe('RB4004 fix - SA without namespace', () => {
  it('generates namespace patch with TODO placeholder', () => {
    const { graph } = analyzeResources2([]);
    const violation = makeViolation({ rule: 'RB4004', resource: 'ServiceAccount/my-sa' });
    const fix = RULE_FIX_MAP.get('RB4004')!(violation, graph, 'en');
    expect(fix).not.toBeNull();
    expect(fix!.yamlPatch).toContain('namespace');
    expect(fix!.autoApplicable).toBe(false);
  });
});

describe('RB4005 fix - SA with no bindings', () => {
  it('generates removal/binding guidance', () => {
    const { graph } = analyzeResources2([]);
    const violation = makeViolation({ rule: 'RB4005', resource: 'ServiceAccount/default/unused-sa' });
    const fix = RULE_FIX_MAP.get('RB4005')!(violation, graph, 'en');
    expect(fix).not.toBeNull();
    expect(fix!.autoApplicable).toBe(false);
  });
});

describe('RB4006 fix - SA bound in multiple namespaces', () => {
  it('generates per-namespace SA template', () => {
    const { graph } = analyzeResources2([]);
    const violation = makeViolation({ rule: 'RB4006', resource: 'ServiceAccount/default/shared-sa' });
    const fix = RULE_FIX_MAP.get('RB4006')!(violation, graph, 'en');
    expect(fix).not.toBeNull();
    expect(fix!.yamlPatch).toContain('ServiceAccount');
    expect(fix!.autoApplicable).toBe(false);
  });
});

describe('RB4007 fix - SA without description', () => {
  it('generates description annotation patch', () => {
    const sa = makeServiceAccount('undescribed', 'default');
    const { graph } = analyzeResources2([sa]);
    const violation = makeViolation({ rule: 'RB4007', resource: 'ServiceAccount/default/undescribed' });
    const fix = RULE_FIX_MAP.get('RB4007')!(violation, graph, 'en');
    expect(fix).not.toBeNull();
    expect(fix!.yamlPatch).toContain('description');
    expect(fix!.autoApplicable).toBe(false);
  });
});

describe('RB4008 fix - SA with automount and no expiry', () => {
  it('generates projected token patch', () => {
    const sa = makeServiceAccount('automount-sa', 'default', true);
    const { graph } = analyzeResources2([sa]);
    const violation = makeViolation({ rule: 'RB4008', resource: 'ServiceAccount/default/automount-sa' });
    const fix = RULE_FIX_MAP.get('RB4008')!(violation, graph, 'en');
    expect(fix).not.toBeNull();
    expect(fix!.yamlPatch).toContain('automountServiceAccountToken');
    expect(fix!.autoApplicable).toBe(false);
  });
});

describe('RB4009 fix - SA can create pods', () => {
  it('returns guidance patch when no binding found', () => {
    const { graph } = analyzeResources2([]);
    const violation = makeViolation({ rule: 'RB4009', resource: 'ServiceAccount/default/pod-creator' });
    const fix = RULE_FIX_MAP.get('RB4009')!(violation, graph, 'en');
    expect(fix).not.toBeNull();
    expect(fix!.autoApplicable).toBe(false);
  });

  it('removes create verb from pods rules when binding+role found', () => {
    const role = makeClusterRole('pod-create-role', [{ apiGroups: [''], resources: ['pods'], verbs: ['create', 'get'] }]);
    const binding = makeClusterBinding('pod-creator', role.metadata.name);
    const { graph } = analyzeResources2([role, binding]);
    const violation = makeViolation({ rule: 'RB4009', resource: 'ServiceAccount/default/pod-creator' });
    const fix = RULE_FIX_MAP.get('RB4009')!(violation, graph, 'en');
    expect(fix).not.toBeNull();
    expect(fix!.yamlPatch).not.toContain('- create');
    expect(fix!.yamlPatch).toContain('get');
    expect(fix!.autoApplicable).toBe(false);
  });
});

describe('RB9001 fix - nodes/status write', () => {
  it('removes nodes/status from resources', () => {
    const role = makeClusterRole('node-status-writer', [{ apiGroups: [''], resources: ['nodes/status'], verbs: ['update'] }]);
    const { graph } = analyzeResources2([role]);
    const violation = makeViolation({ rule: 'RB9001', resource: 'ClusterRole/node-status-writer' });
    const fix = RULE_FIX_MAP.get('RB9001')!(violation, graph, 'en');
    expect(fix).not.toBeNull();
    expect(fix!.yamlPatch).not.toContain('nodes/status');
    expect(fix!.autoApplicable).toBe(false);
  });

  it('returns null when role not found', () => {
    const { graph } = analyzeResources2([]);
    const fix = RULE_FIX_MAP.get('RB9001')!(makeViolation({ rule: 'RB9001', resource: 'ClusterRole/nonexistent' }), graph, 'en');
    expect(fix).toBeNull();
  });

  it('mentions kubelet in explanation', () => {
    const role = makeClusterRole('node-status-writer', [{ apiGroups: [''], resources: ['nodes/status'], verbs: ['update'] }]);
    const { graph } = analyzeResources2([role]);
    const fix = RULE_FIX_MAP.get('RB9001')!(makeViolation({ rule: 'RB9001', resource: 'ClusterRole/node-status-writer' }), graph, 'en');
    expect(fix!.explanation).toContain('kubelet');
  });
});

describe('RB9002 fix - pods/status write', () => {
  it('removes pods/status from resources', () => {
    const role = makeClusterRole('pod-status-writer', [{ apiGroups: [''], resources: ['pods/status'], verbs: ['update'] }]);
    const { graph } = analyzeResources2([role]);
    const violation = makeViolation({ rule: 'RB9002', resource: 'ClusterRole/pod-status-writer' });
    const fix = RULE_FIX_MAP.get('RB9002')!(violation, graph, 'en');
    expect(fix).not.toBeNull();
    expect(fix!.yamlPatch).not.toContain('pods/status');
    expect(fix!.autoApplicable).toBe(false);
  });
});

describe('RB9003 fix - resourcequotas write', () => {
  it('restricts resourcequotas to read-only', () => {
    const role = makeClusterRole('quota-writer', [{ apiGroups: [''], resources: ['resourcequotas'], verbs: ['create', 'delete', 'get'] }]);
    const { graph } = analyzeResources2([role]);
    const violation = makeViolation({ rule: 'RB9003', resource: 'ClusterRole/quota-writer' });
    const fix = RULE_FIX_MAP.get('RB9003')!(violation, graph, 'en');
    expect(fix).not.toBeNull();
    expect(fix!.yamlPatch).not.toContain('create');
    expect(fix!.yamlPatch).not.toContain('delete');
    expect(fix!.autoApplicable).toBe(false);
  });
});

describe('RB9004 fix - limitranges write', () => {
  it('restricts limitranges to read-only', () => {
    const role = makeClusterRole('limit-writer', [{ apiGroups: [''], resources: ['limitranges'], verbs: ['create', 'delete', 'get'] }]);
    const { graph } = analyzeResources2([role]);
    const violation = makeViolation({ rule: 'RB9004', resource: 'ClusterRole/limit-writer' });
    const fix = RULE_FIX_MAP.get('RB9004')!(violation, graph, 'en');
    expect(fix).not.toBeNull();
    expect(fix!.yamlPatch).not.toContain('create');
    expect(fix!.yamlPatch).not.toContain('delete');
    expect(fix!.autoApplicable).toBe(false);
  });
});

describe('generateRuleFixes', () => {
  it('deduplicates same rule+resource violations', () => {
    const role = makeClusterRole('dup-role', [{ apiGroups: [''], resources: ['pods'], verbs: ['*'] }]);
    const { graph } = analyzeResources2([role]);
    const violations: Violation[] = [
      makeViolation({ rule: 'RB1001', resource: 'ClusterRole/dup-role' }),
      makeViolation({ rule: 'RB1001', resource: 'ClusterRole/dup-role' }),
    ];
    const suggestions = generateRuleFixes(violations, graph, 'en');
    expect(suggestions.filter(s => s.ruleId === 'RB1001')).toHaveLength(1);
  });

  it('skips violations without a fix handler', () => {
    const { graph } = analyzeResources2([]);
    const violations: Violation[] = [
      makeViolation({ rule: 'RB1012', resource: 'Role/default/big-role' }),
    ];
    const suggestions = generateRuleFixes(violations, graph, 'en');
    expect(suggestions).toHaveLength(0);
  });

  it('returns null when role not found in graph', () => {
    const { graph } = analyzeResources2([]);
    const violation = makeViolation({ rule: 'RB1001', resource: 'ClusterRole/nonexistent' });
    const fix = RULE_FIX_MAP.get('RB1001')!(violation, graph, 'en');
    expect(fix).toBeNull();
  });
});
