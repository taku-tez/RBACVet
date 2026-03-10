import type { EscalationGraph } from './builder';
import type { ServiceAccountScore } from '../engine/scorer';
export interface PathNode {
    kind: string;
    name: string;
    namespace?: string;
}
export interface EscalationPath {
    serviceAccount: {
        name: string;
        namespace: string;
    };
    path: PathNode[];
    endsAtClusterAdmin: boolean;
    score?: number;
    riskLevel?: string;
}
export declare function extractPaths(graph: EscalationGraph, scores?: ServiceAccountScore[]): EscalationPath[];
