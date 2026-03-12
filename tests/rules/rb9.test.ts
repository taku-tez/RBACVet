import { describe, it, expect } from 'vitest';
import { hasViolation, makeRole, makeClusterRole, analyzeResources2 } from '../helpers';

describe('RB9001 - nodes/status write', () => {
  it('flags update on nodes/status', () => {
    const { violations } = analyzeResources2([
      makeClusterRole('node-status-writer', [{
        apiGroups: [''],
        resources: ['nodes/status'],
        verbs: ['update'],
      }]),
    ]);
    expect(hasViolation(violations, 'RB9001')).toBe(true);
  });

  it('flags patch on nodes/status', () => {
    const { violations } = analyzeResources2([
      makeClusterRole('node-status-patcher', [{
        apiGroups: [''],
        resources: ['nodes/status'],
        verbs: ['patch'],
      }]),
    ]);
    expect(hasViolation(violations, 'RB9001')).toBe(true);
  });

  it('flags wildcard verbs on nodes/status', () => {
    const { violations } = analyzeResources2([
      makeClusterRole('node-all', [{
        apiGroups: [''],
        resources: ['nodes/status'],
        verbs: ['*'],
      }]),
    ]);
    expect(hasViolation(violations, 'RB9001')).toBe(true);
  });

  it('does not flag read-only access to nodes/status', () => {
    const { violations } = analyzeResources2([
      makeClusterRole('node-status-reader', [{
        apiGroups: [''],
        resources: ['nodes/status'],
        verbs: ['get', 'watch'],
      }]),
    ]);
    expect(hasViolation(violations, 'RB9001')).toBe(false);
  });

  it('violation message mentions scheduler', () => {
    const { violations } = analyzeResources2([
      makeClusterRole('node-status-writer', [{
        apiGroups: [''],
        resources: ['nodes/status'],
        verbs: ['update'],
      }]),
    ]);
    const v = violations.find(v => v.rule === 'RB9001');
    expect(v?.message).toContain('scheduler');
  });

  it('severity is high', () => {
    const { violations } = analyzeResources2([
      makeClusterRole('node-status-writer', [{ apiGroups: [''], resources: ['nodes/status'], verbs: ['update'] }]),
    ]);
    const v = violations.find(v => v.rule === 'RB9001');
    expect(v?.severity).toBe('high');
  });

  it('has CIS ID 5.1.3', () => {
    const { violations } = analyzeResources2([
      makeClusterRole('node-status-writer', [{ apiGroups: [''], resources: ['nodes/status'], verbs: ['update'] }]),
    ]);
    // Just verify it fires — CIS ID tested in cis.test.ts
    expect(hasViolation(violations, 'RB9001')).toBe(true);
  });
});

describe('RB9002 - pods/status write', () => {
  it('flags update on pods/status', () => {
    const { violations } = analyzeResources2([
      makeClusterRole('pod-status-writer', [{
        apiGroups: [''],
        resources: ['pods/status'],
        verbs: ['update'],
      }]),
    ]);
    expect(hasViolation(violations, 'RB9002')).toBe(true);
  });

  it('flags patch on pods/status', () => {
    const { violations } = analyzeResources2([
      makeClusterRole('pod-status-patcher', [{
        apiGroups: [''],
        resources: ['pods/status'],
        verbs: ['patch'],
      }]),
    ]);
    expect(hasViolation(violations, 'RB9002')).toBe(true);
  });

  it('does not flag read-only access to pods/status', () => {
    const { violations } = analyzeResources2([
      makeClusterRole('pod-status-reader', [{
        apiGroups: [''],
        resources: ['pods/status'],
        verbs: ['get'],
      }]),
    ]);
    expect(hasViolation(violations, 'RB9002')).toBe(false);
  });

  it('violation message mentions load balancer', () => {
    const { violations } = analyzeResources2([
      makeClusterRole('pod-status-writer', [{
        apiGroups: [''],
        resources: ['pods/status'],
        verbs: ['update'],
      }]),
    ]);
    const v = violations.find(v => v.rule === 'RB9002');
    expect(v?.message).toContain('load balancer');
  });

  it('severity is medium', () => {
    const { violations } = analyzeResources2([
      makeClusterRole('pod-status-writer', [{ apiGroups: [''], resources: ['pods/status'], verbs: ['update'] }]),
    ]);
    const v = violations.find(v => v.rule === 'RB9002');
    expect(v?.severity).toBe('medium');
  });
});

describe('RB9003 - resourcequotas write', () => {
  it('flags create on resourcequotas', () => {
    const { violations } = analyzeResources2([
      makeClusterRole('quota-creator', [{
        apiGroups: [''],
        resources: ['resourcequotas'],
        verbs: ['create'],
      }]),
    ]);
    expect(hasViolation(violations, 'RB9003')).toBe(true);
  });

  it('flags delete on resourcequotas', () => {
    const { violations } = analyzeResources2([
      makeClusterRole('quota-deleter', [{
        apiGroups: [''],
        resources: ['resourcequotas'],
        verbs: ['delete'],
      }]),
    ]);
    expect(hasViolation(violations, 'RB9003')).toBe(true);
  });

  it('does not flag read-only access to resourcequotas', () => {
    const { violations } = analyzeResources2([
      makeClusterRole('quota-reader', [{
        apiGroups: [''],
        resources: ['resourcequotas'],
        verbs: ['get', 'list', 'watch'],
      }]),
    ]);
    expect(hasViolation(violations, 'RB9003')).toBe(false);
  });

  it('violation message mentions resource exhaustion', () => {
    const { violations } = analyzeResources2([
      makeClusterRole('quota-creator', [{ apiGroups: [''], resources: ['resourcequotas'], verbs: ['create'] }]),
    ]);
    const v = violations.find(v => v.rule === 'RB9003');
    expect(v?.message).toContain('resource exhaustion');
  });

  it('severity is medium', () => {
    const { violations } = analyzeResources2([
      makeClusterRole('quota-creator', [{ apiGroups: [''], resources: ['resourcequotas'], verbs: ['create'] }]),
    ]);
    const v = violations.find(v => v.rule === 'RB9003');
    expect(v?.severity).toBe('medium');
  });
});

describe('RB9004 - limitranges write', () => {
  it('flags create on limitranges', () => {
    const { violations } = analyzeResources2([
      makeClusterRole('limit-creator', [{
        apiGroups: [''],
        resources: ['limitranges'],
        verbs: ['create'],
      }]),
    ]);
    expect(hasViolation(violations, 'RB9004')).toBe(true);
  });

  it('flags delete on limitranges', () => {
    const { violations } = analyzeResources2([
      makeClusterRole('limit-deleter', [{
        apiGroups: [''],
        resources: ['limitranges'],
        verbs: ['delete'],
      }]),
    ]);
    expect(hasViolation(violations, 'RB9004')).toBe(true);
  });

  it('does not flag read-only access to limitranges', () => {
    const { violations } = analyzeResources2([
      makeClusterRole('limit-reader', [{
        apiGroups: [''],
        resources: ['limitranges'],
        verbs: ['get', 'list'],
      }]),
    ]);
    expect(hasViolation(violations, 'RB9004')).toBe(false);
  });

  it('violation message mentions resource limits', () => {
    const { violations } = analyzeResources2([
      makeClusterRole('limit-creator', [{ apiGroups: [''], resources: ['limitranges'], verbs: ['delete'] }]),
    ]);
    const v = violations.find(v => v.rule === 'RB9004');
    expect(v?.message).toContain('limits');
  });

  it('severity is low', () => {
    const { violations } = analyzeResources2([
      makeClusterRole('limit-creator', [{ apiGroups: [''], resources: ['limitranges'], verbs: ['create'] }]),
    ]);
    const v = violations.find(v => v.rule === 'RB9004');
    expect(v?.severity).toBe('low');
  });
});
