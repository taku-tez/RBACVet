import type { Violation } from '../rules/types';
import type { ServiceAccountScore } from '../engine/scorer';

export type ViolationDeltaStatus = 'new' | 'fixed' | 'shared';

export interface ViolationDelta {
  violation: Violation;
  status: ViolationDeltaStatus;
}

export interface ScoreDelta {
  name: string;
  scoreA: number;
  scoreB: number;
  delta: number; // scoreB - scoreA
  levelA: string;
  levelB: string;
}

export interface EnvCompareResult {
  contextA: string;
  contextB: string;
  violationDeltas: ViolationDelta[];
  scoreDeltas: ScoreDelta[];
  newCount: number;   // violations in B but not A (regressions)
  fixedCount: number; // violations in A but not B (improvements)
}

function violationKey(v: Violation): string {
  return `${v.rule}::${v.resource}`;
}

// Compare two sets of violations. "new" = in b but not a, "fixed" = in a but not b
export function compareViolations(
  violationsA: Violation[],
  violationsB: Violation[],
  contextA: string,
  contextB: string,
  scoresA: ServiceAccountScore[] = [],
  scoresB: ServiceAccountScore[] = [],
): EnvCompareResult {
  const setA = new Map<string, Violation>();
  for (const v of violationsA) {
    setA.set(violationKey(v), v);
  }

  const setB = new Map<string, Violation>();
  for (const v of violationsB) {
    setB.set(violationKey(v), v);
  }

  const violationDeltas: ViolationDelta[] = [];

  // fixed: in A but not in B
  for (const [key, v] of setA) {
    if (!setB.has(key)) {
      violationDeltas.push({ violation: v, status: 'fixed' });
    } else {
      violationDeltas.push({ violation: v, status: 'shared' });
    }
  }

  // new: in B but not in A
  for (const [key, v] of setB) {
    if (!setA.has(key)) {
      violationDeltas.push({ violation: v, status: 'new' });
    }
  }

  const newCount = violationDeltas.filter(d => d.status === 'new').length;
  const fixedCount = violationDeltas.filter(d => d.status === 'fixed').length;

  // Compute score deltas
  const scoreMapA = new Map<string, ServiceAccountScore>();
  for (const s of scoresA) {
    scoreMapA.set(s.name, s);
  }

  const scoreMapB = new Map<string, ServiceAccountScore>();
  for (const s of scoresB) {
    scoreMapB.set(s.name, s);
  }

  const allNames = new Set<string>([
    ...scoreMapA.keys(),
    ...scoreMapB.keys(),
  ]);

  const scoreDeltas: ScoreDelta[] = [];
  for (const name of allNames) {
    const a = scoreMapA.get(name);
    const b = scoreMapB.get(name);
    const scoreA = a?.score ?? 0;
    const scoreB = b?.score ?? 0;
    const delta = scoreB - scoreA;
    if (delta !== 0) {
      scoreDeltas.push({
        name,
        scoreA,
        scoreB,
        delta,
        levelA: a?.level ?? 'LOW',
        levelB: b?.level ?? 'LOW',
      });
    }
  }

  return {
    contextA,
    contextB,
    violationDeltas,
    scoreDeltas,
    newCount,
    fixedCount,
  };
}
