import { describe, it, expect } from 'vitest';
import { hasViolation, makeRole, makeClusterRole, analyzeResources2 } from '../helpers';

describe('RB8001 - customresourcedefinitions write', () => {
  it('flags create on CRDs with apiextensions.k8s.io', () => {
    const { violations } = analyzeResources2([
      makeClusterRole('crd-creator', [{
        apiGroups: ['apiextensions.k8s.io'],
        resources: ['customresourcedefinitions'],
        verbs: ['create'],
      }]),
    ]);
    expect(hasViolation(violations, 'RB8001')).toBe(true);
  });

  it('flags update on CRDs', () => {
    const { violations } = analyzeResources2([
      makeClusterRole('crd-updater', [{
        apiGroups: ['apiextensions.k8s.io'],
        resources: ['customresourcedefinitions'],
        verbs: ['update'],
      }]),
    ]);
    expect(hasViolation(violations, 'RB8001')).toBe(true);
  });

  it('flags delete on CRDs', () => {
    const { violations } = analyzeResources2([
      makeClusterRole('crd-deleter', [{
        apiGroups: ['apiextensions.k8s.io'],
        resources: ['customresourcedefinitions'],
        verbs: ['delete'],
      }]),
    ]);
    expect(hasViolation(violations, 'RB8001')).toBe(true);
  });

  it('flags wildcard apiGroup with CRD write', () => {
    const { violations } = analyzeResources2([
      makeClusterRole('wildcard-crd', [{
        apiGroups: ['*'],
        resources: ['customresourcedefinitions'],
        verbs: ['create'],
      }]),
    ]);
    expect(hasViolation(violations, 'RB8001')).toBe(true);
  });

  it('flags wildcard resource with apiextensions.k8s.io write', () => {
    const { violations } = analyzeResources2([
      makeClusterRole('wildcard-apiext', [{
        apiGroups: ['apiextensions.k8s.io'],
        resources: ['*'],
        verbs: ['patch'],
      }]),
    ]);
    expect(hasViolation(violations, 'RB8001')).toBe(true);
  });

  it('does not flag read-only access to CRDs', () => {
    const { violations } = analyzeResources2([
      makeClusterRole('crd-reader', [{
        apiGroups: ['apiextensions.k8s.io'],
        resources: ['customresourcedefinitions'],
        verbs: ['get', 'list', 'watch'],
      }]),
    ]);
    expect(hasViolation(violations, 'RB8001')).toBe(false);
  });

  it('does not flag CRD write with wrong apiGroup', () => {
    const { violations } = analyzeResources2([
      makeClusterRole('wrong-group', [{
        apiGroups: ['apps'],
        resources: ['customresourcedefinitions'],
        verbs: ['create'],
      }]),
    ]);
    expect(hasViolation(violations, 'RB8001')).toBe(false);
  });

  it('violation message mentions attack surface', () => {
    const { violations } = analyzeResources2([
      makeClusterRole('crd-creator', [{
        apiGroups: ['apiextensions.k8s.io'],
        resources: ['customresourcedefinitions'],
        verbs: ['create'],
      }]),
    ]);
    const v = violations.find(v => v.rule === 'RB8001');
    expect(v?.message).toContain('attack surface');
  });

  it('severity is medium', () => {
    const { violations } = analyzeResources2([
      makeClusterRole('crd-creator', [{
        apiGroups: ['apiextensions.k8s.io'],
        resources: ['customresourcedefinitions'],
        verbs: ['create'],
      }]),
    ]);
    const v = violations.find(v => v.rule === 'RB8001');
    expect(v?.severity).toBe('medium');
  });
});

describe('RB8002 - daemonsets write', () => {
  it('flags create on daemonsets with apps apiGroup', () => {
    const { violations } = analyzeResources2([
      makeClusterRole('ds-creator', [{
        apiGroups: ['apps'],
        resources: ['daemonsets'],
        verbs: ['create'],
      }]),
    ]);
    expect(hasViolation(violations, 'RB8002')).toBe(true);
  });

  it('flags update on daemonsets', () => {
    const { violations } = analyzeResources2([
      makeClusterRole('ds-updater', [{
        apiGroups: ['apps'],
        resources: ['daemonsets'],
        verbs: ['update'],
      }]),
    ]);
    expect(hasViolation(violations, 'RB8002')).toBe(true);
  });

  it('flags wildcard apiGroup with daemonset write', () => {
    const { violations } = analyzeResources2([
      makeClusterRole('wildcard-ds', [{
        apiGroups: ['*'],
        resources: ['daemonsets'],
        verbs: ['create'],
      }]),
    ]);
    expect(hasViolation(violations, 'RB8002')).toBe(true);
  });

  it('flags wildcard resource with apps group write', () => {
    const { violations } = analyzeResources2([
      makeClusterRole('wildcard-apps', [{
        apiGroups: ['apps'],
        resources: ['*'],
        verbs: ['delete'],
      }]),
    ]);
    expect(hasViolation(violations, 'RB8002')).toBe(true);
  });

  it('does not flag read-only access to daemonsets', () => {
    const { violations } = analyzeResources2([
      makeClusterRole('ds-reader', [{
        apiGroups: ['apps'],
        resources: ['daemonsets'],
        verbs: ['get', 'list', 'watch'],
      }]),
    ]);
    expect(hasViolation(violations, 'RB8002')).toBe(false);
  });

  it('does not flag daemonset write with wrong apiGroup', () => {
    const { violations } = analyzeResources2([
      makeClusterRole('wrong-group-ds', [{
        apiGroups: [''],
        resources: ['daemonsets'],
        verbs: ['create'],
      }]),
    ]);
    expect(hasViolation(violations, 'RB8002')).toBe(false);
  });

  it('violation message mentions every node', () => {
    const { violations } = analyzeResources2([
      makeClusterRole('ds-creator', [{
        apiGroups: ['apps'],
        resources: ['daemonsets'],
        verbs: ['create'],
      }]),
    ]);
    const v = violations.find(v => v.rule === 'RB8002');
    expect(v?.message).toContain('every node');
  });

  it('severity is high', () => {
    const { violations } = analyzeResources2([
      makeClusterRole('ds-creator', [{
        apiGroups: ['apps'],
        resources: ['daemonsets'],
        verbs: ['create'],
      }]),
    ]);
    const v = violations.find(v => v.rule === 'RB8002');
    expect(v?.severity).toBe('high');
  });
});

describe('RB8003 - priorityclasses write', () => {
  it('flags create on priorityclasses with scheduling.k8s.io', () => {
    const { violations } = analyzeResources2([
      makeClusterRole('pc-creator', [{
        apiGroups: ['scheduling.k8s.io'],
        resources: ['priorityclasses'],
        verbs: ['create'],
      }]),
    ]);
    expect(hasViolation(violations, 'RB8003')).toBe(true);
  });

  it('flags update on priorityclasses', () => {
    const { violations } = analyzeResources2([
      makeClusterRole('pc-updater', [{
        apiGroups: ['scheduling.k8s.io'],
        resources: ['priorityclasses'],
        verbs: ['update'],
      }]),
    ]);
    expect(hasViolation(violations, 'RB8003')).toBe(true);
  });

  it('flags wildcard apiGroup with priorityclass write', () => {
    const { violations } = analyzeResources2([
      makeClusterRole('wildcard-pc', [{
        apiGroups: ['*'],
        resources: ['priorityclasses'],
        verbs: ['create'],
      }]),
    ]);
    expect(hasViolation(violations, 'RB8003')).toBe(true);
  });

  it('does not flag read-only access to priorityclasses', () => {
    const { violations } = analyzeResources2([
      makeClusterRole('pc-reader', [{
        apiGroups: ['scheduling.k8s.io'],
        resources: ['priorityclasses'],
        verbs: ['get', 'list'],
      }]),
    ]);
    expect(hasViolation(violations, 'RB8003')).toBe(false);
  });

  it('does not flag priorityclass write with wrong apiGroup', () => {
    const { violations } = analyzeResources2([
      makeClusterRole('wrong-group-pc', [{
        apiGroups: ['apps'],
        resources: ['priorityclasses'],
        verbs: ['create'],
      }]),
    ]);
    expect(hasViolation(violations, 'RB8003')).toBe(false);
  });

  it('violation message mentions system-critical pods', () => {
    const { violations } = analyzeResources2([
      makeClusterRole('pc-creator', [{
        apiGroups: ['scheduling.k8s.io'],
        resources: ['priorityclasses'],
        verbs: ['create'],
      }]),
    ]);
    const v = violations.find(v => v.rule === 'RB8003');
    expect(v?.message).toContain('system-critical');
  });

  it('severity is low', () => {
    const { violations } = analyzeResources2([
      makeClusterRole('pc-creator', [{
        apiGroups: ['scheduling.k8s.io'],
        resources: ['priorityclasses'],
        verbs: ['create'],
      }]),
    ]);
    const v = violations.find(v => v.rule === 'RB8003');
    expect(v?.severity).toBe('low');
  });
});

describe('RB8004 - batch/jobs write', () => {
  it('flags create on jobs with batch apiGroup', () => {
    const { violations } = analyzeResources2([
      makeClusterRole('job-creator', [{
        apiGroups: ['batch'],
        resources: ['jobs'],
        verbs: ['create'],
      }]),
    ]);
    expect(hasViolation(violations, 'RB8004')).toBe(true);
  });

  it('flags create on cronjobs with batch apiGroup', () => {
    const { violations } = analyzeResources2([
      makeClusterRole('cronjob-creator', [{
        apiGroups: ['batch'],
        resources: ['cronjobs'],
        verbs: ['create'],
      }]),
    ]);
    expect(hasViolation(violations, 'RB8004')).toBe(true);
  });

  it('flags wildcard apiGroup with job write', () => {
    const { violations } = analyzeResources2([
      makeClusterRole('wildcard-job', [{
        apiGroups: ['*'],
        resources: ['jobs'],
        verbs: ['update'],
      }]),
    ]);
    expect(hasViolation(violations, 'RB8004')).toBe(true);
  });

  it('does not flag read-only access to jobs', () => {
    const { violations } = analyzeResources2([
      makeClusterRole('job-reader', [{
        apiGroups: ['batch'],
        resources: ['jobs'],
        verbs: ['get', 'list', 'watch'],
      }]),
    ]);
    expect(hasViolation(violations, 'RB8004')).toBe(false);
  });

  it('does not flag job write with wrong apiGroup', () => {
    const { violations } = analyzeResources2([
      makeClusterRole('wrong-group-job', [{
        apiGroups: [''],
        resources: ['jobs'],
        verbs: ['create'],
      }]),
    ]);
    expect(hasViolation(violations, 'RB8004')).toBe(false);
  });

  it('severity is medium', () => {
    const { violations } = analyzeResources2([
      makeClusterRole('job-creator', [{ apiGroups: ['batch'], resources: ['jobs'], verbs: ['create'] }]),
    ]);
    const v = violations.find(v => v.rule === 'RB8004');
    expect(v?.severity).toBe('medium');
  });
});

describe('RB8005 - statefulsets write', () => {
  it('flags create on statefulsets with apps apiGroup', () => {
    const { violations } = analyzeResources2([
      makeClusterRole('sts-creator', [{
        apiGroups: ['apps'],
        resources: ['statefulsets'],
        verbs: ['create'],
      }]),
    ]);
    expect(hasViolation(violations, 'RB8005')).toBe(true);
  });

  it('flags wildcard apiGroup with statefulset write', () => {
    const { violations } = analyzeResources2([
      makeClusterRole('wildcard-sts', [{
        apiGroups: ['*'],
        resources: ['statefulsets'],
        verbs: ['patch'],
      }]),
    ]);
    expect(hasViolation(violations, 'RB8005')).toBe(true);
  });

  it('does not flag read-only access to statefulsets', () => {
    const { violations } = analyzeResources2([
      makeClusterRole('sts-reader', [{
        apiGroups: ['apps'],
        resources: ['statefulsets'],
        verbs: ['get', 'list', 'watch'],
      }]),
    ]);
    expect(hasViolation(violations, 'RB8005')).toBe(false);
  });

  it('does not flag statefulset write with wrong apiGroup', () => {
    const { violations } = analyzeResources2([
      makeClusterRole('wrong-group-sts', [{
        apiGroups: [''],
        resources: ['statefulsets'],
        verbs: ['create'],
      }]),
    ]);
    expect(hasViolation(violations, 'RB8005')).toBe(false);
  });

  it('severity is medium', () => {
    const { violations } = analyzeResources2([
      makeClusterRole('sts-creator', [{ apiGroups: ['apps'], resources: ['statefulsets'], verbs: ['create'] }]),
    ]);
    const v = violations.find(v => v.rule === 'RB8005');
    expect(v?.severity).toBe('medium');
  });
});

describe('RB8006 - horizontalpodautoscalers write', () => {
  it('flags update on HPAs with autoscaling apiGroup', () => {
    const { violations } = analyzeResources2([
      makeClusterRole('hpa-scaler', [{
        apiGroups: ['autoscaling'],
        resources: ['horizontalpodautoscalers'],
        verbs: ['update'],
      }]),
    ]);
    expect(hasViolation(violations, 'RB8006')).toBe(true);
  });

  it('flags wildcard apiGroup with HPA write', () => {
    const { violations } = analyzeResources2([
      makeClusterRole('wildcard-hpa', [{
        apiGroups: ['*'],
        resources: ['horizontalpodautoscalers'],
        verbs: ['patch'],
      }]),
    ]);
    expect(hasViolation(violations, 'RB8006')).toBe(true);
  });

  it('does not flag read-only access to HPAs', () => {
    const { violations } = analyzeResources2([
      makeClusterRole('hpa-reader', [{
        apiGroups: ['autoscaling'],
        resources: ['horizontalpodautoscalers'],
        verbs: ['get', 'list'],
      }]),
    ]);
    expect(hasViolation(violations, 'RB8006')).toBe(false);
  });

  it('does not flag HPA write with wrong apiGroup', () => {
    const { violations } = analyzeResources2([
      makeClusterRole('wrong-group-hpa', [{
        apiGroups: ['apps'],
        resources: ['horizontalpodautoscalers'],
        verbs: ['update'],
      }]),
    ]);
    expect(hasViolation(violations, 'RB8006')).toBe(false);
  });

  it('violation message mentions scale', () => {
    const { violations } = analyzeResources2([
      makeClusterRole('hpa-scaler', [{ apiGroups: ['autoscaling'], resources: ['horizontalpodautoscalers'], verbs: ['update'] }]),
    ]);
    const v = violations.find(v => v.rule === 'RB8006');
    expect(v?.message).toContain('scaling');
  });

  it('severity is low', () => {
    const { violations } = analyzeResources2([
      makeClusterRole('hpa-scaler', [{ apiGroups: ['autoscaling'], resources: ['horizontalpodautoscalers'], verbs: ['update'] }]),
    ]);
    const v = violations.find(v => v.rule === 'RB8006');
    expect(v?.severity).toBe('low');
  });
});
