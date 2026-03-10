import type { ResourceGraph } from '../rules/types';
import type { Violation } from '../rules/types';
export type RiskLevel = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
export interface ServiceAccountScore {
    name: string;
    score: number;
    level: RiskLevel;
    reasons: string[];
    escalationPath?: string[];
}
export interface ScoringResult {
    scores: ServiceAccountScore[];
    maxScore: number;
    exceededThreshold: boolean;
}
export declare function computeScores(graph: ResourceGraph, violations: Violation[], threshold: number, trusted: string[]): ScoringResult;
