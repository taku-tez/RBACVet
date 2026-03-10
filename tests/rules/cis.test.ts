import { describe, it, expect } from 'vitest';
import { RULE_MAP } from '../../src/rules/index';
import { enrichViolationsWithCIS } from '../../src/rules/cis';
import type { Violation } from '../../src/rules/types';

describe('CIS Kubernetes Benchmark mapping', () => {
  it('RULE_MAP has cisId on RB1001 (CIS 5.1.3)', () => {
    expect(RULE_MAP.get('RB1001')?.cisId).toBe('CIS 5.1.3');
  });

  it('RULE_MAP has cisId on RB1002 (CIS 5.1.3)', () => {
    expect(RULE_MAP.get('RB1002')?.cisId).toBe('CIS 5.1.3');
  });

  it('RULE_MAP has cisId on RB2001 (CIS 5.1.1)', () => {
    expect(RULE_MAP.get('RB2001')?.cisId).toBe('CIS 5.1.1');
  });

  it('RULE_MAP has cisId on RB3001 (CIS 5.1.2)', () => {
    expect(RULE_MAP.get('RB3001')?.cisId).toBe('CIS 5.1.2');
  });

  it('RULE_MAP has cisId on RB3002 (CIS 5.1.2)', () => {
    expect(RULE_MAP.get('RB3002')?.cisId).toBe('CIS 5.1.2');
  });

  it('RULE_MAP has cisId on RB4001 (CIS 5.1.6)', () => {
    expect(RULE_MAP.get('RB4001')?.cisId).toBe('CIS 5.1.6');
  });

  it('rules without CIS mapping have no cisId', () => {
    expect(RULE_MAP.get('RB1003')?.cisId).toBeUndefined();
  });
});

describe('enrichViolationsWithCIS', () => {
  const baseViolation: Violation = {
    rule: 'RB1001',
    severity: 'error',
    message: 'test message',
    resource: 'ClusterRole/test',
    file: 'test.yaml',
    line: 1,
  };

  it('adds cisId to violations when rule has one', () => {
    const enriched = enrichViolationsWithCIS([baseViolation], RULE_MAP);
    expect(enriched).toHaveLength(1);
    expect(enriched[0].cisId).toBe('CIS 5.1.3');
  });

  it('does not add cisId when rule has none', () => {
    const violation: Violation = { ...baseViolation, rule: 'RB1003' };
    const enriched = enrichViolationsWithCIS([violation], RULE_MAP);
    expect(enriched).toHaveLength(1);
    expect(enriched[0].cisId).toBeUndefined();
  });

  it('preserves other violation fields', () => {
    const enriched = enrichViolationsWithCIS([baseViolation], RULE_MAP);
    const v = enriched[0];
    expect(v.rule).toBe('RB1001');
    expect(v.severity).toBe('error');
    expect(v.message).toBe('test message');
    expect(v.resource).toBe('ClusterRole/test');
    expect(v.file).toBe('test.yaml');
    expect(v.line).toBe(1);
  });

  it('handles violations with unknown rule gracefully', () => {
    const violation: Violation = { ...baseViolation, rule: 'UNKNOWN999' };
    const enriched = enrichViolationsWithCIS([violation], RULE_MAP);
    expect(enriched).toHaveLength(1);
    expect(enriched[0].cisId).toBeUndefined();
  });

  it('handles empty violations array', () => {
    const enriched = enrichViolationsWithCIS([], RULE_MAP);
    expect(enriched).toHaveLength(0);
  });
});
