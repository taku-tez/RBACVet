import type { Violation } from '../rules/types';
import type { ServiceAccountScore } from '../engine/scorer';
import type { K8sResource } from '../parser/types';

export interface JSONOutput {
  violations: Violation[];
  riskScores: ServiceAccountScore[];
  summary: {
    errors: number;
    warnings: number;
    infos: number;
    filesScanned: number;
    resourcesFound: Record<string, number>;
  };
}

export function formatJSON(
  violations: Violation[],
  scores: ServiceAccountScore[],
  filesScanned: number,
  resources: K8sResource[],
): string {
  const resourcesFound: Record<string, number> = {};
  for (const r of resources) {
    resourcesFound[r.kind] = (resourcesFound[r.kind] || 0) + 1;
  }

  const output: JSONOutput = {
    violations,
    riskScores: scores,
    summary: {
      errors: violations.filter(v => v.severity === 'error').length,
      warnings: violations.filter(v => v.severity === 'warning').length,
      infos: violations.filter(v => v.severity === 'info').length,
      filesScanned,
      resourcesFound,
    },
  };

  return JSON.stringify(output, null, 2);
}
