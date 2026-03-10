import type { Severity } from '../rules/types';
export interface SeverityOverride {
    severity: Severity;
}
export interface RBACVetConfig {
    ignore: string[];
    override: Record<string, SeverityOverride>;
    riskScoreThreshold: number;
    trustedClusterAdminBindings: string[];
}
export declare function loadConfig(configPath?: string): RBACVetConfig;
