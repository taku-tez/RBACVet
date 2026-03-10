import { describe, it, expect } from 'vitest';
import { generateRuleFixes, RULE_FIX_MAP } from '../../src/fix/rule-fixes';
import { makeClusterRole, makeRole, makeServiceAccount, analyzeResources2 } from '../helpers';
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
  it('has entries for RB1001, RB1002, RB2001, RB3001, RB3002, RB4001, IS1001', () => {
    expect(RULE_FIX_MAP.has('RB1001')).toBe(true);
    expect(RULE_FIX_MAP.has('RB1002')).toBe(true);
    expect(RULE_FIX_MAP.has('RB2001')).toBe(true);
    expect(RULE_FIX_MAP.has('RB3001')).toBe(true);
    expect(RULE_FIX_MAP.has('RB3002')).toBe(true);
    expect(RULE_FIX_MAP.has('RB4001')).toBe(true);
    expect(RULE_FIX_MAP.has('IS1001')).toBe(true);
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
