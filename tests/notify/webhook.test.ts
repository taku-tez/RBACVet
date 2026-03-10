import { describe, it, expect } from 'vitest';
import { buildWebhookPayload } from '../../src/notify/webhook';
import type { Violation } from '../../src/rules/types';
import type { ServiceAccountScore } from '../../src/engine/scorer';
import type { FilterResult } from '../../src/policy/types';

function makeViolation(rule: string, severity: Violation['severity'] = 'error'): Violation {
  return { rule, severity, message: 'test', resource: 'ClusterRole/foo', file: 'test.yaml', line: 1 };
}

function makeScore(name: string, score: number, level: ServiceAccountScore['level']): ServiceAccountScore {
  return { name, score, level, reasons: [] };
}

const emptyFilter: FilterResult = { remaining: [], exempted: [], expiredExemptions: [] };

describe('buildWebhookPayload', () => {
  it('counts errors, warnings, infos correctly', () => {
    const violations = [
      makeViolation('RB1001', 'error'),
      makeViolation('RB1002', 'error'),
      makeViolation('RB3001', 'warning'),
      makeViolation('RB4001', 'info'),
    ];
    const payload = buildWebhookPayload(violations, [], emptyFilter, 5);
    expect(payload.summary.errors).toBe(2);
    expect(payload.summary.warnings).toBe(1);
    expect(payload.summary.infos).toBe(1);
    expect(payload.summary.filesScanned).toBe(5);
  });

  it('uses correct source and version', () => {
    const payload = buildWebhookPayload([], [], emptyFilter, 0, '0.5.0');
    expect(payload.source).toBe('rbacvet');
    expect(payload.version).toBe('0.5.0');
  });

  it('computes maxRiskScore from top score', () => {
    const scores = [makeScore('sa1', 90, 'CRITICAL'), makeScore('sa2', 50, 'MEDIUM')];
    const payload = buildWebhookPayload([], scores, emptyFilter, 0);
    expect(payload.summary.maxRiskScore).toBe(90);
    expect(payload.summary.maxRiskLevel).toBe('CRITICAL');
  });

  it('includes exempted count from filterResult', () => {
    const filter: FilterResult = {
      remaining: [],
      exempted: [{ violation: makeViolation('RB1001'), exemption: { rule: 'RB1001', resource: '*', reason: 'ok', author: 'alice', isExpired: false } }],
      expiredExemptions: [],
    };
    const payload = buildWebhookPayload([], [], filter, 0);
    expect(payload.summary.exempted).toBe(1);
  });

  it('topViolations capped at 5 and sorted by severity', () => {
    const violations = [
      makeViolation('RB5001', 'info'),
      makeViolation('RB5002', 'info'),
      makeViolation('RB1001', 'error'),
      makeViolation('RB1002', 'error'),
      makeViolation('RB3001', 'warning'),
      makeViolation('RB3002', 'warning'),
    ];
    const payload = buildWebhookPayload(violations, [], emptyFilter, 0);
    expect(payload.topViolations).toHaveLength(5);
    expect(payload.topViolations[0].severity).toBe('error');
  });

  it('topRiskyAccounts capped at 3', () => {
    const scores = [
      makeScore('sa1', 90, 'CRITICAL'),
      makeScore('sa2', 70, 'HIGH'),
      makeScore('sa3', 50, 'MEDIUM'),
      makeScore('sa4', 30, 'LOW'),
    ];
    const payload = buildWebhookPayload([], scores, emptyFilter, 0);
    expect(payload.topRiskyAccounts).toHaveLength(3);
    expect(payload.topRiskyAccounts[0].name).toBe('sa1');
  });

  it('maxRiskLevel is LOW when no scores', () => {
    const payload = buildWebhookPayload([], [], emptyFilter, 0);
    expect(payload.summary.maxRiskScore).toBe(0);
    expect(payload.summary.maxRiskLevel).toBe('LOW');
  });

  it('includes timestamp as ISO string', () => {
    const payload = buildWebhookPayload([], [], emptyFilter, 0);
    expect(() => new Date(payload.timestamp)).not.toThrow();
    expect(payload.timestamp).toMatch(/^\d{4}-\d{2}-\d{2}T/);
  });
});
