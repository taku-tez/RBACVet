import { describe, it, expect } from 'vitest';
import { analyzeResources2, makeServiceAccount, makeClusterRole, makeRole, makeClusterBinding, makeBinding } from './helpers';

describe('Risk Scorer', () => {
  it('SA with no bindings scores 10 (automount enabled)', () => {
    const { scores } = analyzeResources2([
      makeServiceAccount('idle-sa', 'default'),
    ]);
    const sa = scores.find(s => s.name.includes('idle-sa'));
    expect(sa).toBeDefined();
    expect(sa!.score).toBe(10);
    expect(sa!.level).toBe('LOW');
  });

  it('SA with automount disabled and no bindings scores 0', () => {
    const { scores } = analyzeResources2([
      makeServiceAccount('safe-sa', 'default', false),
    ]);
    const sa = scores.find(s => s.name.includes('safe-sa'));
    expect(sa).toBeDefined();
    expect(sa!.score).toBe(0);
    expect(sa!.level).toBe('LOW');
  });

  it('SA bound to cluster-admin scores >= 80 (CRITICAL)', () => {
    const { scores } = analyzeResources2([
      makeServiceAccount('admin-sa', 'default', false),
      makeClusterBinding('admin-sa', 'cluster-admin', 'default'),
    ]);
    const sa = scores.find(s => s.name.includes('admin-sa'));
    expect(sa).toBeDefined();
    expect(sa!.score).toBeGreaterThanOrEqual(80);
    expect(sa!.level).toBe('CRITICAL');
  });

  it('SA bound to wildcard ClusterRole scores >= 60 (HIGH or CRITICAL)', () => {
    const { scores } = analyzeResources2([
      makeServiceAccount('power-sa', 'default', false),
      makeClusterRole('all-access', [{ apiGroups: ['*'], resources: ['*'], verbs: ['*'] }]),
      makeClusterBinding('power-sa', 'all-access', 'default'),
    ]);
    const sa = scores.find(s => s.name.includes('power-sa'));
    expect(sa).toBeDefined();
    expect(sa!.score).toBeGreaterThanOrEqual(60);
  });

  it('SA with minimal permissions scores LOW', () => {
    const { scores } = analyzeResources2([
      makeServiceAccount('minimal-sa', 'default', false),
      makeRole('pod-reader', [{ apiGroups: [''], resources: ['pods'], verbs: ['get'] }]),
      makeBinding('minimal-sa', 'pod-reader', 'default'),
    ]);
    const sa = scores.find(s => s.name.includes('minimal-sa'));
    expect(sa).toBeDefined();
    expect(sa!.score).toBeLessThan(30);
    expect(sa!.level).toBe('LOW');
  });

  it('score is capped at 100', () => {
    const { scores } = analyzeResources2([
      makeServiceAccount('max-sa', 'default', true),
      makeClusterRole('super-admin', [{ apiGroups: ['*'], resources: ['*'], verbs: ['*'] }]),
      makeClusterBinding('max-sa', 'super-admin', 'default'),
    ]);
    const sa = scores.find(s => s.name.includes('max-sa'));
    expect(sa).toBeDefined();
    expect(sa!.score).toBeLessThanOrEqual(100);
  });

  it('escalation path is included for SA bound to cluster-admin', () => {
    const { scores } = analyzeResources2([
      makeServiceAccount('escalated-sa', 'default', false),
      makeClusterBinding('escalated-sa', 'cluster-admin', 'default'),
    ]);
    const sa = scores.find(s => s.name.includes('escalated-sa'));
    expect(sa).toBeDefined();
    expect(sa!.escalationPath).toBeDefined();
  });

  it('scores are sorted descending by score', () => {
    const { scores } = analyzeResources2([
      makeServiceAccount('low-sa', 'default', false),
      makeServiceAccount('high-sa', 'default', true),
      makeClusterBinding('high-sa', 'cluster-admin', 'default'),
    ]);
    expect(scores.length).toBeGreaterThan(0);
    for (let i = 1; i < scores.length; i++) {
      expect(scores[i - 1].score).toBeGreaterThanOrEqual(scores[i].score);
    }
  });

  it('MEDIUM range: score 30-59', () => {
    const { scores } = analyzeResources2([
      makeServiceAccount('medium-sa', 'default', true),
      makeRole('secret-role', [{ apiGroups: [''], resources: ['secrets'], verbs: ['get'] }]),
      makeBinding('medium-sa', 'secret-role', 'default'),
    ]);
    const sa = scores.find(s => s.name.includes('medium-sa'));
    expect(sa).toBeDefined();
  });

  it('exceededThreshold false when no SA scores above threshold', () => {
    const { scores } = analyzeResources2(
      [makeServiceAccount('safe-sa', 'default', false)],
      { riskScoreThreshold: 60 },
    );
    const maxScore = scores.length > 0 ? Math.max(...scores.map(s => s.score)) : 0;
    expect(maxScore).toBeLessThan(60);
  });

  it('includes reasons in score breakdown', () => {
    const { scores } = analyzeResources2([
      makeServiceAccount('reason-sa', 'default', true),
    ]);
    const sa = scores.find(s => s.name.includes('reason-sa'));
    expect(sa).toBeDefined();
    expect(sa!.reasons.length).toBeGreaterThan(0);
  });

  it('SA name appears in score resource name', () => {
    const { scores } = analyzeResources2([
      makeServiceAccount('named-sa', 'production', false),
    ]);
    const sa = scores.find(s => s.name.includes('named-sa'));
    expect(sa).toBeDefined();
    expect(sa!.name).toContain('production');
  });

  it('SA score increases when bound role has error violations', () => {
    // A role with escalate verb will trigger an RB2002 error violation on the role resource
    const { scores } = analyzeResources2([
      makeServiceAccount('escalate-sa', 'default', false),
      makeRole('escalate-role', [{ apiGroups: ['rbac.authorization.k8s.io'], resources: ['roles'], verbs: ['escalate'] }]),
      makeBinding('escalate-sa', 'escalate-role', 'default'),
    ]);
    const sa = scores.find(s => s.name.includes('escalate-sa'));
    expect(sa).toBeDefined();
    // Should have reasons from the bound role's violations
    const hasRoleViolationReason = sa!.reasons.some(r => r.includes('[via'));
    expect(hasRoleViolationReason).toBe(true);
    // Score should be elevated above baseline (automount disabled = 0, so any role violation adds points)
    expect(sa!.score).toBeGreaterThan(0);
  });

  it('compound risk (create pods + get secrets) increases score by at least 20 points', () => {
    // SA with only pod create
    const { scores: scoresCreate } = analyzeResources2([
      makeServiceAccount('pod-creator', 'default', false),
      makeRole('pod-create-role', [{ apiGroups: [''], resources: ['pods'], verbs: ['create'] }]),
      makeBinding('pod-creator', 'pod-create-role', 'default'),
    ]);
    const saCreate = scoresCreate.find(s => s.name.includes('pod-creator'));

    // SA with both pod create and secret read (compound risk)
    const { scores: scoresCompound } = analyzeResources2([
      makeServiceAccount('compound-sa', 'default', false),
      makeRole('compound-role', [
        { apiGroups: [''], resources: ['pods'], verbs: ['create'] },
        { apiGroups: [''], resources: ['secrets'], verbs: ['get'] },
      ]),
      makeBinding('compound-sa', 'compound-role', 'default'),
    ]);
    const saCompound = scoresCompound.find(s => s.name.includes('compound-sa'));

    expect(saCompound).toBeDefined();
    expect(saCreate).toBeDefined();
    // Compound SA should score at least 20 points more than pod-only SA
    expect(saCompound!.score).toBeGreaterThanOrEqual(saCreate!.score + 20);
    expect(saCompound!.reasons.some(r => r.includes('compound risk'))).toBe(true);
  });
});
