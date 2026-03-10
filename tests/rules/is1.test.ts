import { describe, it, expect } from 'vitest';
import { IS1001, IS1002, IS1003, IS1004 } from '../../src/rules/is1/istio';
import { makeAuthorizationPolicy, analyzeResources2, hasViolation } from '../helpers';
import { RULE_MAP } from '../../src/rules/index';

describe('IS1001 - ALLOW with no rules', () => {
  it('flags ALLOW policy with no rules', () => {
    const policy = makeAuthorizationPolicy('open-policy', { action: 'ALLOW' });
    const { violations } = analyzeResources2([policy]);
    expect(hasViolation(violations, 'IS1001')).toBe(true);
  });

  it('flags ALLOW policy with empty rules array', () => {
    const policy = makeAuthorizationPolicy('open-policy', { action: 'ALLOW', rules: [] });
    const { violations } = analyzeResources2([policy]);
    expect(hasViolation(violations, 'IS1001')).toBe(true);
  });

  it('does not flag ALLOW policy with rules defined', () => {
    const policy = makeAuthorizationPolicy('restricted', {
      action: 'ALLOW',
      rules: [{ from: [{ source: { principals: ['cluster.local/ns/default/sa/app'] } }] }],
    });
    const { violations } = analyzeResources2([policy]);
    expect(hasViolation(violations, 'IS1001')).toBe(false);
  });

  it('does not flag DENY policy with no rules', () => {
    const policy = makeAuthorizationPolicy('deny-all', { action: 'DENY' });
    const { violations } = analyzeResources2([policy]);
    expect(hasViolation(violations, 'IS1001')).toBe(false);
  });

  it('defaults to ALLOW when action is missing', () => {
    const policy = makeAuthorizationPolicy('implicit-allow', {});
    const { violations } = analyzeResources2([policy]);
    expect(hasViolation(violations, 'IS1001')).toBe(true);
  });
});

describe('IS1002 - wildcard principal', () => {
  it('flags wildcard principal in ALLOW rule', () => {
    const policy = makeAuthorizationPolicy('wild-principal', {
      action: 'ALLOW',
      rules: [{ from: [{ source: { principals: ['*'] } }] }],
    });
    const { violations } = analyzeResources2([policy]);
    expect(hasViolation(violations, 'IS1002')).toBe(true);
  });

  it('does not fire for DENY policy with wildcard principal (deny-all-then-allow pattern)', () => {
    const policy = makeAuthorizationPolicy('deny-wild', {
      action: 'DENY',
      rules: [{ from: [{ source: { principals: ['*'] } }] }],
    });
    const { violations } = analyzeResources2([policy]);
    expect(hasViolation(violations, 'IS1002')).toBe(false);
  });

  it('does not flag specific principal', () => {
    const policy = makeAuthorizationPolicy('specific', {
      action: 'ALLOW',
      rules: [{ from: [{ source: { principals: ['cluster.local/ns/default/sa/app'] } }] }],
    });
    const { violations } = analyzeResources2([policy]);
    expect(hasViolation(violations, 'IS1002')).toBe(false);
  });
});

describe('IS1003 - wildcard HTTP method', () => {
  it('flags wildcard method', () => {
    const policy = makeAuthorizationPolicy('wild-method', {
      action: 'ALLOW',
      rules: [{ to: [{ operation: { methods: ['*'] } }] }],
    });
    const { violations } = analyzeResources2([policy]);
    expect(hasViolation(violations, 'IS1003')).toBe(true);
  });

  it('does not flag specific methods', () => {
    const policy = makeAuthorizationPolicy('get-only', {
      action: 'ALLOW',
      rules: [{ to: [{ operation: { methods: ['GET', 'HEAD'] } }] }],
    });
    const { violations } = analyzeResources2([policy]);
    expect(hasViolation(violations, 'IS1003')).toBe(false);
  });
});

describe('IS1004 - wildcard namespace', () => {
  it('flags wildcard namespace', () => {
    const policy = makeAuthorizationPolicy('wild-ns', {
      action: 'ALLOW',
      rules: [{ from: [{ source: { namespaces: ['*'] } }] }],
    });
    const { violations } = analyzeResources2([policy]);
    expect(hasViolation(violations, 'IS1004')).toBe(true);
  });

  it('does not flag specific namespace', () => {
    const policy = makeAuthorizationPolicy('specific-ns', {
      action: 'ALLOW',
      rules: [{ from: [{ source: { namespaces: ['production'] } }] }],
    });
    const { violations } = analyzeResources2([policy]);
    expect(hasViolation(violations, 'IS1004')).toBe(false);
  });
});

describe('Istio YAML parsing', () => {
  it('IS rules appear in RULE_MAP', () => {
    expect(RULE_MAP.has('IS1001')).toBe(true);
    expect(RULE_MAP.has('IS1002')).toBe(true);
    expect(RULE_MAP.has('IS1003')).toBe(true);
    expect(RULE_MAP.has('IS1004')).toBe(true);
  });
});
