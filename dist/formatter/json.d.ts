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
export declare function formatJSON(violations: Violation[], scores: ServiceAccountScore[], filesScanned: number, resources: K8sResource[]): string;
