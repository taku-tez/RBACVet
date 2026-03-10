import type { Violation } from '../rules/types';
import type { ServiceAccountScore } from '../engine/scorer';
import type { K8sResource } from '../parser/types';

export interface JSONOutput {
  violations: Violation[];
  riskScores: ServiceAccountScore[];
  summary: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
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
      critical: violations.filter(v => v.severity === 'critical').length,
      high: violations.filter(v => v.severity === 'high').length,
      medium: violations.filter(v => v.severity === 'medium').length,
      low: violations.filter(v => v.severity === 'low').length,
      info: violations.filter(v => v.severity === 'info').length,
      filesScanned,
      resourcesFound,
    },
  };

  return JSON.stringify(output, null, 2);
}
