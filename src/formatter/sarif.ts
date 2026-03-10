import type { Violation } from '../rules/types';
import { RULE_MAP } from '../rules/index';

const SEVERITY_MAP: Record<string, string> = {
  critical: 'error',
  high: 'error',
  medium: 'warning',
  low: 'note',
  info: 'note',
};

export function formatSARIF(violations: Violation[]): string {
  const usedRules = new Set(violations.map(v => v.rule));
  const rules = Array.from(usedRules).map(id => {
    const rule = RULE_MAP.get(id);
    const entry: Record<string, unknown> = {
      id,
      shortDescription: { text: rule?.description || id },
      defaultConfiguration: { level: SEVERITY_MAP[rule?.severity || 'info'] || 'note' },
    };
    if (rule?.cisId) {
      entry.properties = { tags: [rule.cisId] };
    }
    return entry;
  });

  const sarif = {
    $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
    version: '2.1.0',
    runs: [{
      tool: {
        driver: {
          name: 'rbacvet',
          version: '0.5.0',
          informationUri: 'https://github.com/RBACVet/rbacvet',
          rules,
        },
      },
      results: violations.map(v => ({
        ruleId: v.rule,
        level: SEVERITY_MAP[v.severity] || 'note',
        message: { text: v.message },
        locations: [{
          physicalLocation: {
            artifactLocation: { uri: v.file },
            region: { startLine: Math.max(v.line, 1), startColumn: 1 },
          },
        }],
      })),
    }],
  };

  return JSON.stringify(sarif, null, 2);
}
