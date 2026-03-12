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

  it('RULE_MAP has cisId on RB1003 (CIS 5.1.3)', () => {
    expect(RULE_MAP.get('RB1003')?.cisId).toBe('CIS 5.1.3');
  });

  it('RULE_MAP has cisId on RB2002 (CIS 5.1.8)', () => {
    expect(RULE_MAP.get('RB2002')?.cisId).toBe('CIS 5.1.8');
  });

  it('RULE_MAP has cisId on RB2003 (CIS 5.1.8)', () => {
    expect(RULE_MAP.get('RB2003')?.cisId).toBe('CIS 5.1.8');
  });

  it('RULE_MAP has cisId on RB2006 (CIS 5.1.8)', () => {
    expect(RULE_MAP.get('RB2006')?.cisId).toBe('CIS 5.1.8');
  });

  it('RULE_MAP has cisId on RB3009 (CIS 5.1.2)', () => {
    expect(RULE_MAP.get('RB3009')?.cisId).toBe('CIS 5.1.2');
  });

  it('RULE_MAP has cisId on RB4002 (CIS 5.1.5)', () => {
    expect(RULE_MAP.get('RB4002')?.cisId).toBe('CIS 5.1.5');
  });

  it('RULE_MAP has cisId on RB4009 (CIS 5.1.4)', () => {
    expect(RULE_MAP.get('RB4009')?.cisId).toBe('CIS 5.1.4');
  });

  it('RULE_MAP has cisId on RB6002 (CIS 5.1.7)', () => {
    expect(RULE_MAP.get('RB6002')?.cisId).toBe('CIS 5.1.7');
  });

  // RB1 expansions
  it('RULE_MAP has cisId on RB1004 (CIS 5.1.3)', () => {
    expect(RULE_MAP.get('RB1004')?.cisId).toBe('CIS 5.1.3');
  });

  it('RULE_MAP has cisId on RB1005 (CIS 5.1.3)', () => {
    expect(RULE_MAP.get('RB1005')?.cisId).toBe('CIS 5.1.3');
  });

  it('RULE_MAP has cisId on RB1006 (CIS 5.1.3)', () => {
    expect(RULE_MAP.get('RB1006')?.cisId).toBe('CIS 5.1.3');
  });

  it('RULE_MAP has cisId on RB1009 (CIS 5.1.3)', () => {
    expect(RULE_MAP.get('RB1009')?.cisId).toBe('CIS 5.1.3');
  });

  it('RULE_MAP has cisId on RB1010 (CIS 5.1.3)', () => {
    expect(RULE_MAP.get('RB1010')?.cisId).toBe('CIS 5.1.3');
  });

  // RB2 expansions
  it('RULE_MAP has cisId on RB2004 (CIS 5.1.8)', () => {
    expect(RULE_MAP.get('RB2004')?.cisId).toBe('CIS 5.1.8');
  });

  it('RULE_MAP has cisId on RB2005 (CIS 5.1.8)', () => {
    expect(RULE_MAP.get('RB2005')?.cisId).toBe('CIS 5.1.8');
  });

  it('RULE_MAP has cisId on RB2007 (CIS 5.1.8)', () => {
    expect(RULE_MAP.get('RB2007')?.cisId).toBe('CIS 5.1.8');
  });

  it('RULE_MAP has cisId on RB2010 (CIS 5.1.1)', () => {
    expect(RULE_MAP.get('RB2010')?.cisId).toBe('CIS 5.1.1');
  });

  it('RULE_MAP has cisId on RB2011 (CIS 5.1.3)', () => {
    expect(RULE_MAP.get('RB2011')?.cisId).toBe('CIS 5.1.3');
  });

  it('RULE_MAP has cisId on RB2012 (CIS 5.1.8)', () => {
    expect(RULE_MAP.get('RB2012')?.cisId).toBe('CIS 5.1.8');
  });

  // RB3 expansions
  it('RULE_MAP has cisId on RB3004 (CIS 5.1.2)', () => {
    expect(RULE_MAP.get('RB3004')?.cisId).toBe('CIS 5.1.2');
  });

  it('RULE_MAP has cisId on RB3011 (CIS 5.1.2)', () => {
    expect(RULE_MAP.get('RB3011')?.cisId).toBe('CIS 5.1.2');
  });

  // RB4 expansions
  it('RULE_MAP has cisId on RB4003 (CIS 5.1.5)', () => {
    expect(RULE_MAP.get('RB4003')?.cisId).toBe('CIS 5.1.5');
  });

  // RB5 expansions
  it('RULE_MAP has cisId on RB5001 (CIS 5.1.1)', () => {
    expect(RULE_MAP.get('RB5001')?.cisId).toBe('CIS 5.1.1');
  });

  it('RULE_MAP has cisId on RB5002 (CIS 5.1.1)', () => {
    expect(RULE_MAP.get('RB5002')?.cisId).toBe('CIS 5.1.1');
  });

  // RB6 expansions
  it('RULE_MAP has cisId on RB6003 (CIS 5.3.2)', () => {
    expect(RULE_MAP.get('RB6003')?.cisId).toBe('CIS 5.3.2');
  });

  // RB7 expansions
  it('RULE_MAP has cisId on RB7001 (CIS 5.1.3)', () => {
    expect(RULE_MAP.get('RB7001')?.cisId).toBe('CIS 5.1.3');
  });

  it('RULE_MAP has cisId on RB7002 (CIS 5.1.3)', () => {
    expect(RULE_MAP.get('RB7002')?.cisId).toBe('CIS 5.1.3');
  });

  // RB9 expansions
  it('RULE_MAP has cisId on RB9001 (CIS 5.1.3)', () => {
    expect(RULE_MAP.get('RB9001')?.cisId).toBe('CIS 5.1.3');
  });

  it('rules without CIS mapping have no cisId', () => {
    expect(RULE_MAP.get('RB1007')?.cisId).toBeUndefined();
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
    const violation: Violation = { ...baseViolation, rule: 'RB1007' };
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
