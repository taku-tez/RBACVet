import { describe, it, expect } from 'vitest';
import { compareViolations } from '../../src/cluster/compare';
import type { Violation } from '../../src/rules/types';

function makeViolation(rule: string, resource: string, overrides: Partial<Violation> = {}): Violation {
  return {
    rule,
    resource,
    severity: 'warning',
    message: `Test violation for ${rule}`,
    file: 'test.yaml',
    line: 1,
    ...overrides,
  };
}

describe('compareViolations', () => {
  it('violations only in B are marked new', () => {
    const violationsA: Violation[] = [];
    const violationsB = [makeViolation('RB001', 'Role/default/my-role')];

    const result = compareViolations(violationsA, violationsB, 'ctx-a', 'ctx-b');

    expect(result.violationDeltas).toHaveLength(1);
    expect(result.violationDeltas[0].status).toBe('new');
    expect(result.violationDeltas[0].violation.rule).toBe('RB001');
  });

  it('violations only in A are marked fixed', () => {
    const violationsA = [makeViolation('RB001', 'Role/default/my-role')];
    const violationsB: Violation[] = [];

    const result = compareViolations(violationsA, violationsB, 'ctx-a', 'ctx-b');

    expect(result.violationDeltas).toHaveLength(1);
    expect(result.violationDeltas[0].status).toBe('fixed');
    expect(result.violationDeltas[0].violation.rule).toBe('RB001');
  });

  it('violations in both A and B are marked shared', () => {
    const v = makeViolation('RB002', 'ClusterRole/admin');
    const violationsA = [v];
    const violationsB = [{ ...v, file: 'different.yaml', line: 99 }];

    const result = compareViolations(violationsA, violationsB, 'ctx-a', 'ctx-b');

    expect(result.violationDeltas).toHaveLength(1);
    expect(result.violationDeltas[0].status).toBe('shared');
  });

  it('newCount and fixedCount are correct', () => {
    const violationsA = [
      makeViolation('RB001', 'Role/default/role-a'),
      makeViolation('RB002', 'Role/default/role-b'),
    ];
    const violationsB = [
      makeViolation('RB002', 'Role/default/role-b'), // shared
      makeViolation('RB003', 'Role/default/role-c'), // new
    ];

    const result = compareViolations(violationsA, violationsB, 'ctx-a', 'ctx-b');

    expect(result.newCount).toBe(1);
    expect(result.fixedCount).toBe(1);
  });

  it('empty sets produce empty deltas', () => {
    const result = compareViolations([], [], 'ctx-a', 'ctx-b');

    expect(result.violationDeltas).toHaveLength(0);
    expect(result.newCount).toBe(0);
    expect(result.fixedCount).toBe(0);
  });

  it('contextA and contextB are preserved in result', () => {
    const result = compareViolations([], [], 'dev-cluster', 'prod-cluster');

    expect(result.contextA).toBe('dev-cluster');
    expect(result.contextB).toBe('prod-cluster');
  });

  it('violation identity is based on rule + resource, not file or line', () => {
    const violationsA = [makeViolation('RB001', 'Role/ns/role', { file: 'a.yaml', line: 10 })];
    const violationsB = [makeViolation('RB001', 'Role/ns/role', { file: 'b.yaml', line: 99 })];

    const result = compareViolations(violationsA, violationsB, 'ctx-a', 'ctx-b');

    expect(result.violationDeltas).toHaveLength(1);
    expect(result.violationDeltas[0].status).toBe('shared');
    expect(result.newCount).toBe(0);
    expect(result.fixedCount).toBe(0);
  });

  it('multiple new violations are all marked new', () => {
    const violationsA: Violation[] = [];
    const violationsB = [
      makeViolation('RB001', 'Role/ns/role-1'),
      makeViolation('RB002', 'Role/ns/role-2'),
      makeViolation('RB003', 'Role/ns/role-3'),
    ];

    const result = compareViolations(violationsA, violationsB, 'ctx-a', 'ctx-b');

    expect(result.newCount).toBe(3);
    expect(result.fixedCount).toBe(0);
    expect(result.violationDeltas.every(d => d.status === 'new')).toBe(true);
  });
});
