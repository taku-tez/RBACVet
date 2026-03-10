import { describe, it, expect } from 'vitest';
import * as path from 'path';
import { analyzeFiles } from '../src/engine/analyzer';
import { formatTTY } from '../src/formatter/tty';
import { formatJSON } from '../src/formatter/json';
import { formatSARIF } from '../src/formatter/sarif';
import { formatHTML } from '../src/formatter/html';
import { enrichViolationsWithCIS } from '../src/rules/cis';
import { RULE_MAP } from '../src/rules/index';
import type { RBACVetConfig } from '../src/engine/config';

const CLEAN_DIR = path.join(__dirname, 'fixtures/clean');
const VIOLATIONS_DIR = path.join(__dirname, 'fixtures/violations');

const DEFAULT_CONFIG: RBACVetConfig = {
  ignore: [],
  override: {},
  riskScoreThreshold: 60,
  trustedClusterAdminBindings: [],
};

describe('Integration: clean fixtures', () => {
  it('produces no errors on clean role fixture', () => {
    const files = [path.join(CLEAN_DIR, 'minimal-role.yaml')];
    const result = analyzeFiles(files, DEFAULT_CONFIG);
    const errors = result.violations.filter(v => v.severity === 'critical' || v.severity === 'high');
    expect(errors).toHaveLength(0);
  });

  it('parses resources from clean fixture', () => {
    const files = [path.join(CLEAN_DIR, 'minimal-role.yaml')];
    const result = analyzeFiles(files, DEFAULT_CONFIG);
    expect(result.parseErrors).toHaveLength(0);
  });
});

describe('Integration: violations fixtures', () => {
  it('detects RB1001 in wildcard-role.yaml', () => {
    const files = [path.join(VIOLATIONS_DIR, 'wildcard-role.yaml')];
    const result = analyzeFiles(files, DEFAULT_CONFIG);
    const rb1001 = result.violations.filter(v => v.rule === 'RB1001');
    expect(rb1001.length).toBeGreaterThan(0);
  });

  it('detects RB2001 in cluster-admin-binding.yaml', () => {
    const files = [path.join(VIOLATIONS_DIR, 'cluster-admin-binding.yaml')];
    const result = analyzeFiles(files, DEFAULT_CONFIG);
    const rb2001 = result.violations.filter(v => v.rule === 'RB2001');
    expect(rb2001.length).toBeGreaterThan(0);
  });
});

describe('Integration: ignore config', () => {
  it('ignores RB5005 when configured', () => {
    const files = [path.join(VIOLATIONS_DIR, 'wildcard-role.yaml')];
    const result = analyzeFiles(files, { ...DEFAULT_CONFIG, ignore: ['RB5005'] });
    const rb5005 = result.violations.filter(v => v.rule === 'RB5005');
    expect(rb5005).toHaveLength(0);
  });
});

describe('Integration: severity override', () => {
  it('overrides RB3001 severity to critical', () => {
    const files = [path.join(CLEAN_DIR, 'minimal-role.yaml')];
    const config: RBACVetConfig = {
      ...DEFAULT_CONFIG,
      override: { RB3001: { severity: 'critical' } },
    };
    const result = analyzeFiles(files, config);
    const rb3001 = result.violations.filter(v => v.rule === 'RB3001');
    rb3001.forEach(v => expect(v.severity).toBe('critical'));
  });
});

describe('Integration: JSON formatter', () => {
  it('produces valid JSON output', () => {
    const files = [path.join(VIOLATIONS_DIR, 'wildcard-role.yaml')];
    const result = analyzeFiles(files, DEFAULT_CONFIG);
    const resources = [...result.graph.roles.values(), ...result.graph.clusterRoles.values()];
    const json = formatJSON(result.violations, result.scores, files.length, resources);
    expect(() => JSON.parse(json)).not.toThrow();
    const parsed = JSON.parse(json);
    expect(parsed).toHaveProperty('violations');
    expect(parsed).toHaveProperty('riskScores');
    expect(parsed).toHaveProperty('summary');
  });

  it('JSON summary has correct error count', () => {
    const files = [path.join(VIOLATIONS_DIR, 'wildcard-role.yaml')];
    const result = analyzeFiles(files, DEFAULT_CONFIG);
    const resources = [...result.graph.roles.values()];
    const json = formatJSON(result.violations, result.scores, files.length, resources);
    const parsed = JSON.parse(json);
    expect(parsed.summary.critical + parsed.summary.high).toBeGreaterThan(0);
  });
});

describe('Integration: SARIF formatter', () => {
  it('produces valid SARIF 2.1 output', () => {
    const files = [path.join(VIOLATIONS_DIR, 'wildcard-role.yaml')];
    const result = analyzeFiles(files, DEFAULT_CONFIG);
    const sarif = formatSARIF(result.violations);
    expect(() => JSON.parse(sarif)).not.toThrow();
    const parsed = JSON.parse(sarif);
    expect(parsed.version).toBe('2.1.0');
    expect(parsed.runs).toHaveLength(1);
    expect(parsed.runs[0].tool.driver.name).toBe('rbacvet');
  });

  it('SARIF results have required fields', () => {
    const files = [path.join(VIOLATIONS_DIR, 'wildcard-role.yaml')];
    const result = analyzeFiles(files, DEFAULT_CONFIG);
    const sarif = formatSARIF(result.violations);
    const parsed = JSON.parse(sarif);
    const results = parsed.runs[0].results;
    expect(results.length).toBeGreaterThan(0);
    for (const r of results) {
      expect(r).toHaveProperty('ruleId');
      expect(r).toHaveProperty('level');
      expect(r).toHaveProperty('message');
      expect(r).toHaveProperty('locations');
    }
  });
});

describe('Integration: TTY formatter', () => {
  it('produces non-empty output for violations', () => {
    const files = [path.join(VIOLATIONS_DIR, 'wildcard-role.yaml')];
    const result = analyzeFiles(files, DEFAULT_CONFIG);
    const tty = formatTTY(result.violations, result.scores, false);
    expect(tty.length).toBeGreaterThan(0);
  });

  it('shows "No violations found" for clean files', () => {
    const files = [path.join(CLEAN_DIR, 'minimal-role.yaml')];
    const result = analyzeFiles(files, DEFAULT_CONFIG);
    // Filter to critical/high only
    const errorOnly = result.violations.filter(v => v.severity === 'critical' || v.severity === 'high');
    const tty = formatTTY(errorOnly, [], false);
    expect(tty).toContain('No violations found');
  });
});

describe('Integration: risk scores', () => {
  it('cluster-admin binding produces CRITICAL score', () => {
    const files = [path.join(VIOLATIONS_DIR, 'cluster-admin-binding.yaml')];
    const result = analyzeFiles(files, DEFAULT_CONFIG);
    const critical = result.scores.filter(s => s.level === 'CRITICAL');
    expect(critical.length).toBeGreaterThan(0);
  });
});

describe('Integration: Istio AuthorizationPolicy', () => {
  it('detects IS1001 in istio-policy.yaml (allow-all)', () => {
    const files = [path.join(VIOLATIONS_DIR, 'istio-policy.yaml')];
    const result = analyzeFiles(files, DEFAULT_CONFIG);
    const is1001 = result.violations.filter(v => v.rule === 'IS1001');
    expect(is1001.length).toBeGreaterThan(0);
  });

  it('detects IS1002 in istio-policy.yaml (wildcard principal)', () => {
    const files = [path.join(VIOLATIONS_DIR, 'istio-policy.yaml')];
    const result = analyzeFiles(files, DEFAULT_CONFIG);
    const is1002 = result.violations.filter(v => v.rule === 'IS1002');
    expect(is1002.length).toBeGreaterThan(0);
  });

  it('produces no IS1001/IS1002 violations for clean Istio policy', () => {
    const files = [path.join(CLEAN_DIR, 'istio-restricted.yaml')];
    const result = analyzeFiles(files, DEFAULT_CONFIG);
    const istioErrors = result.violations.filter(v => v.rule === 'IS1001' || v.rule === 'IS1002');
    expect(istioErrors).toHaveLength(0);
  });
});

describe('Integration: CIS enrichment', () => {
  it('enrichViolationsWithCIS adds cisId to RB1001 violations', () => {
    const files = [path.join(VIOLATIONS_DIR, 'wildcard-role.yaml')];
    const result = analyzeFiles(files, DEFAULT_CONFIG);
    const enriched = enrichViolationsWithCIS(result.violations, RULE_MAP);
    const rb1001 = enriched.find(v => v.rule === 'RB1001');
    expect(rb1001).toBeDefined();
    expect(rb1001!.cisId).toBe('CIS 5.1.3');
  });
});

describe('Integration: SARIF CIS tags', () => {
  it('SARIF includes CIS tags for rules with cisId', () => {
    const files = [path.join(VIOLATIONS_DIR, 'wildcard-role.yaml')];
    const result = analyzeFiles(files, DEFAULT_CONFIG);
    const sarif = formatSARIF(result.violations);
    const parsed = JSON.parse(sarif);
    const rb1001Rule = parsed.runs[0].tool.driver.rules.find((r: { id: string }) => r.id === 'RB1001');
    expect(rb1001Rule).toBeDefined();
    expect(rb1001Rule.properties.tags).toContain('CIS 5.1.3');
  });

  it('SARIF version is 0.5.0', () => {
    const sarif = formatSARIF([]);
    const parsed = JSON.parse(sarif);
    expect(parsed.runs[0].tool.driver.version).toBe('0.5.0');
  });
});

describe('Integration: HTML formatter', () => {
  it('produces valid HTML output', () => {
    const files = [path.join(VIOLATIONS_DIR, 'wildcard-role.yaml')];
    const result = analyzeFiles(files, DEFAULT_CONFIG);
    const html = formatHTML(result.violations, result.scores, { ruleMap: RULE_MAP, filesScanned: 1 });
    expect(html).toContain('<!DOCTYPE html>');
    expect(html).toContain('rbacvet');
  });

  it('HTML shows CIS badge for violations with CIS ID', () => {
    const files = [path.join(VIOLATIONS_DIR, 'wildcard-role.yaml')];
    const result = analyzeFiles(files, DEFAULT_CONFIG);
    const html = formatHTML(result.violations, result.scores, { ruleMap: RULE_MAP });
    expect(html).toContain('CIS 5.1.3');
  });
});
