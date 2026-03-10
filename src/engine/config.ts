import * as fs from 'fs';
import * as path from 'path';
import * as yaml from 'js-yaml';
import type { Severity } from '../rules/types';

export interface SeverityOverride {
  severity: Severity;
}

export interface RBACVetConfig {
  ignore: string[];
  override: Record<string, SeverityOverride>;
  riskScoreThreshold: number;
  trustedClusterAdminBindings: string[];
  notifyUrl?: string;
}

const DEFAULT_CONFIG: RBACVetConfig = {
  ignore: [],
  override: {},
  riskScoreThreshold: 60,
  trustedClusterAdminBindings: [],
};

export function loadConfig(configPath?: string): RBACVetConfig {
  const searchPaths = configPath
    ? [configPath]
    : [
        path.join(process.cwd(), '.rbacvet.yaml'),
        path.join(process.cwd(), '.rbacvet.yml'),
      ];

  for (const p of searchPaths) {
    if (fs.existsSync(p)) {
      try {
        const content = fs.readFileSync(p, 'utf-8');
        const raw = yaml.load(content) as Partial<RBACVetConfig> | null;
        if (raw && typeof raw === 'object') {
          return {
            ignore: Array.isArray(raw.ignore) ? raw.ignore : DEFAULT_CONFIG.ignore,
            override: raw.override ?? DEFAULT_CONFIG.override,
            riskScoreThreshold: typeof raw.riskScoreThreshold === 'number'
              ? raw.riskScoreThreshold
              : DEFAULT_CONFIG.riskScoreThreshold,
            trustedClusterAdminBindings: Array.isArray(raw.trustedClusterAdminBindings)
              ? raw.trustedClusterAdminBindings
              : DEFAULT_CONFIG.trustedClusterAdminBindings,
            notifyUrl: raw.notifyUrl as string | undefined,
          };
        }
      } catch {
        // ignore config parse errors, use defaults
      }
    }
  }

  return { ...DEFAULT_CONFIG, ignore: [], override: {}, trustedClusterAdminBindings: [] };
}
