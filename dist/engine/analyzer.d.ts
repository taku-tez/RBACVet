import type { K8sResource, ParseError } from '../parser/types';
import type { Violation, ResourceGraph } from '../rules/types';
import type { RBACVetConfig } from './config';
import type { ServiceAccountScore } from './scorer';
export interface AnalysisResult {
    violations: Violation[];
    scores: ServiceAccountScore[];
    graph: ResourceGraph;
    parseErrors: ParseError[];
}
export declare function analyzeResources(resources: K8sResource[], config: RBACVetConfig): Omit<AnalysisResult, 'parseErrors'>;
export declare function analyzeFiles(files: string[], config: RBACVetConfig): AnalysisResult;
export declare function collectYamlFiles(dir: string): string[];
