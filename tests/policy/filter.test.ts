import { describe, it, expect } from 'vitest';
import { applyExemptions } from '../../src/policy/filter';
import type { Violation } from '../../src/rules/types';
import type { PolicyFile } from '../../src/policy/types';

function makeViolation(rule: string, resource: string, severity: Violation['severity'] = 'error'): Violation {
  return { rule, severity, message: 'test', resource, file: 'test.yaml', line: 1 };
}

function makePolicy(exemptions: PolicyFile['exemptions']): PolicyFile {
  return { version: '1', exemptions };
}

describe('applyExemptions', () => {
  it('returns all violations when policy is null', () => {
    const violations = [makeViolation('RB1001', 'ClusterRole/foo')];
    const result = applyExemptions(violations, null);
    expect(result.remaining).toHaveLength(1);
    expect(result.exempted).toHaveLength(0);
  });

  it('exempts matching rule+resource', () => {
    const violations = [makeViolation('RB1001', 'ClusterRole/foo')];
    const policy = makePolicy([{
      rule: 'RB1001',
      resource: 'ClusterRole/foo',
      reason: 'legacy',
      author: 'alice',
    }]);
    const result = applyExemptions(violations, policy);
    expect(result.remaining).toHaveLength(0);
    expect(result.exempted).toHaveLength(1);
    expect(result.exempted[0].exemption.reason).toBe('legacy');
  });

  it('does not exempt non-matching resource', () => {
    const violations = [makeViolation('RB1001', 'ClusterRole/bar')];
    const policy = makePolicy([{
      rule: 'RB1001',
      resource: 'ClusterRole/foo',
      reason: 'legacy',
      author: 'alice',
    }]);
    const result = applyExemptions(violations, policy);
    expect(result.remaining).toHaveLength(1);
    expect(result.exempted).toHaveLength(0);
  });

  it('wildcard rule matches any rule', () => {
    const violations = [
      makeViolation('RB1001', 'ClusterRole/foo'),
      makeViolation('RB2001', 'ClusterRole/foo'),
    ];
    const policy = makePolicy([{
      rule: '*',
      resource: 'ClusterRole/foo',
      reason: 'trusted',
      author: 'bob',
    }]);
    const result = applyExemptions(violations, policy);
    expect(result.remaining).toHaveLength(0);
    expect(result.exempted).toHaveLength(2);
  });

  it('wildcard resource matches any resource', () => {
    const violations = [
      makeViolation('RB1001', 'ClusterRole/foo'),
      makeViolation('RB1001', 'ClusterRole/bar'),
    ];
    const policy = makePolicy([{
      rule: 'RB1001',
      resource: '*',
      reason: 'global ignore',
      author: 'alice',
    }]);
    const result = applyExemptions(violations, policy);
    expect(result.remaining).toHaveLength(0);
    expect(result.exempted).toHaveLength(2);
  });

  it('does not apply expired exemption', () => {
    const violations = [makeViolation('RB1001', 'ClusterRole/foo')];
    const policy = makePolicy([{
      rule: 'RB1001',
      resource: 'ClusterRole/foo',
      reason: 'old',
      author: 'alice',
      expires: '2020-01-01',
    }]);
    const now = new Date('2025-01-01');
    const result = applyExemptions(violations, policy, now);
    expect(result.remaining).toHaveLength(1);
    expect(result.exempted).toHaveLength(0);
    expect(result.expiredExemptions).toHaveLength(1);
    expect(result.expiredExemptions[0].reason).toBe('old');
  });

  it('applies non-expired exemption', () => {
    const violations = [makeViolation('RB1001', 'ClusterRole/foo')];
    const policy = makePolicy([{
      rule: 'RB1001',
      resource: 'ClusterRole/foo',
      reason: 'current',
      author: 'alice',
      expires: '2030-12-31',
    }]);
    const now = new Date('2025-01-01');
    const result = applyExemptions(violations, policy, now);
    expect(result.remaining).toHaveLength(0);
    expect(result.exempted).toHaveLength(1);
    expect(result.expiredExemptions).toHaveLength(0);
  });

  it('keeps violations for non-exempted rules', () => {
    const violations = [
      makeViolation('RB1001', 'ClusterRole/foo'),
      makeViolation('RB2001', 'ClusterRoleBinding/binding'),
    ];
    const policy = makePolicy([{
      rule: 'RB1001',
      resource: 'ClusterRole/foo',
      reason: 'ok',
      author: 'alice',
    }]);
    const result = applyExemptions(violations, policy);
    expect(result.remaining).toHaveLength(1);
    expect(result.remaining[0].rule).toBe('RB2001');
    expect(result.exempted).toHaveLength(1);
  });
});
