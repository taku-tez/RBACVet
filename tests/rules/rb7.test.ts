import { describe, it, expect } from 'vitest';
import { hasViolation, makeRole, makeClusterRole, analyzeResources2 } from '../helpers';

describe('RB7001 - admission webhook configuration write access', () => {
  it('flags create on validatingwebhookconfigurations', () => {
    const { violations } = analyzeResources2([
      makeClusterRole('webhook-creator', [{
        apiGroups: ['admissionregistration.k8s.io'],
        resources: ['validatingwebhookconfigurations'],
        verbs: ['create'],
      }]),
    ]);
    expect(hasViolation(violations, 'RB7001')).toBe(true);
  });

  it('flags update on mutatingwebhookconfigurations', () => {
    const { violations } = analyzeResources2([
      makeClusterRole('webhook-updater', [{
        apiGroups: ['admissionregistration.k8s.io'],
        resources: ['mutatingwebhookconfigurations'],
        verbs: ['update'],
      }]),
    ]);
    expect(hasViolation(violations, 'RB7001')).toBe(true);
  });

  it('flags delete on validatingwebhookconfigurations', () => {
    const { violations } = analyzeResources2([
      makeClusterRole('webhook-deleter', [{
        apiGroups: ['admissionregistration.k8s.io'],
        resources: ['validatingwebhookconfigurations'],
        verbs: ['delete'],
      }]),
    ]);
    expect(hasViolation(violations, 'RB7001')).toBe(true);
  });

  it('flags patch on mutatingwebhookconfigurations', () => {
    const { violations } = analyzeResources2([
      makeClusterRole('webhook-patcher', [{
        apiGroups: ['admissionregistration.k8s.io'],
        resources: ['mutatingwebhookconfigurations'],
        verbs: ['patch'],
      }]),
    ]);
    expect(hasViolation(violations, 'RB7001')).toBe(true);
  });

  it('flags wildcard apiGroup with webhook resource write', () => {
    const { violations } = analyzeResources2([
      makeClusterRole('wildcard-webhook', [{
        apiGroups: ['*'],
        resources: ['validatingwebhookconfigurations'],
        verbs: ['create'],
      }]),
    ]);
    expect(hasViolation(violations, 'RB7001')).toBe(true);
  });

  it('flags wildcard resource with admissionregistration.k8s.io group write', () => {
    const { violations } = analyzeResources2([
      makeClusterRole('wildcard-admission', [{
        apiGroups: ['admissionregistration.k8s.io'],
        resources: ['*'],
        verbs: ['delete'],
      }]),
    ]);
    expect(hasViolation(violations, 'RB7001')).toBe(true);
  });

  it('does not flag read-only access to webhook configurations', () => {
    const { violations } = analyzeResources2([
      makeClusterRole('webhook-reader', [{
        apiGroups: ['admissionregistration.k8s.io'],
        resources: ['validatingwebhookconfigurations'],
        verbs: ['get', 'list', 'watch'],
      }]),
    ]);
    expect(hasViolation(violations, 'RB7001')).toBe(false);
  });

  it('does not flag write to unrelated admissionregistration resources', () => {
    const { violations } = analyzeResources2([
      makeRole('pod-writer', [{
        apiGroups: [''],
        resources: ['pods'],
        verbs: ['create', 'update'],
      }]),
    ]);
    expect(hasViolation(violations, 'RB7001')).toBe(false);
  });

  it('does not flag write to webhook with unrelated apiGroup', () => {
    const { violations } = analyzeResources2([
      makeClusterRole('wrong-group', [{
        apiGroups: ['apps'],
        resources: ['validatingwebhookconfigurations'],
        verbs: ['create'],
      }]),
    ]);
    expect(hasViolation(violations, 'RB7001')).toBe(false);
  });

  it('violation message mentions OPA Gatekeeper or Kyverno', () => {
    const { violations } = analyzeResources2([
      makeClusterRole('webhook-deleter', [{
        apiGroups: ['admissionregistration.k8s.io'],
        resources: ['validatingwebhookconfigurations'],
        verbs: ['delete'],
      }]),
    ]);
    const v = violations.find(v => v.rule === 'RB7001');
    expect(v?.message).toContain('OPA Gatekeeper');
  });

  it('violation severity is high', () => {
    const { violations } = analyzeResources2([
      makeClusterRole('webhook-deleter', [{
        apiGroups: ['admissionregistration.k8s.io'],
        resources: ['validatingwebhookconfigurations'],
        verbs: ['delete'],
      }]),
    ]);
    const v = violations.find(v => v.rule === 'RB7001');
    expect(v?.severity).toBe('high');
  });
});

describe('RB7002 - runtimeclasses write', () => {
  it('flags create on runtimeclasses with node.k8s.io', () => {
    const { violations } = analyzeResources2([
      makeClusterRole('rc-creator', [{
        apiGroups: ['node.k8s.io'],
        resources: ['runtimeclasses'],
        verbs: ['create'],
      }]),
    ]);
    expect(hasViolation(violations, 'RB7002')).toBe(true);
  });

  it('flags update on runtimeclasses', () => {
    const { violations } = analyzeResources2([
      makeClusterRole('rc-updater', [{
        apiGroups: ['node.k8s.io'],
        resources: ['runtimeclasses'],
        verbs: ['update'],
      }]),
    ]);
    expect(hasViolation(violations, 'RB7002')).toBe(true);
  });

  it('flags wildcard apiGroup with runtimeclass write', () => {
    const { violations } = analyzeResources2([
      makeClusterRole('wildcard-rc', [{
        apiGroups: ['*'],
        resources: ['runtimeclasses'],
        verbs: ['patch'],
      }]),
    ]);
    expect(hasViolation(violations, 'RB7002')).toBe(true);
  });

  it('flags wildcard resource with node.k8s.io write', () => {
    const { violations } = analyzeResources2([
      makeClusterRole('wildcard-node', [{
        apiGroups: ['node.k8s.io'],
        resources: ['*'],
        verbs: ['delete'],
      }]),
    ]);
    expect(hasViolation(violations, 'RB7002')).toBe(true);
  });

  it('does not flag read-only access to runtimeclasses', () => {
    const { violations } = analyzeResources2([
      makeClusterRole('rc-reader', [{
        apiGroups: ['node.k8s.io'],
        resources: ['runtimeclasses'],
        verbs: ['get', 'list', 'watch'],
      }]),
    ]);
    expect(hasViolation(violations, 'RB7002')).toBe(false);
  });

  it('does not flag runtimeclass write with wrong apiGroup', () => {
    const { violations } = analyzeResources2([
      makeClusterRole('wrong-group-rc', [{
        apiGroups: ['apps'],
        resources: ['runtimeclasses'],
        verbs: ['create'],
      }]),
    ]);
    expect(hasViolation(violations, 'RB7002')).toBe(false);
  });

  it('violation message mentions sandbox isolation', () => {
    const { violations } = analyzeResources2([
      makeClusterRole('rc-creator', [{
        apiGroups: ['node.k8s.io'],
        resources: ['runtimeclasses'],
        verbs: ['create'],
      }]),
    ]);
    const v = violations.find(v => v.rule === 'RB7002');
    expect(v?.message).toContain('sandbox');
  });

  it('severity is high', () => {
    const { violations } = analyzeResources2([
      makeClusterRole('rc-creator', [{
        apiGroups: ['node.k8s.io'],
        resources: ['runtimeclasses'],
        verbs: ['create'],
      }]),
    ]);
    const v = violations.find(v => v.rule === 'RB7002');
    expect(v?.severity).toBe('high');
  });
});
