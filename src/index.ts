#!/usr/bin/env node

import * as fs from 'fs';
import { analyzeFiles, collectYamlFiles, analyzeResources } from './engine/analyzer';
import { loadConfig } from './engine/config';
import { formatTTY } from './formatter/tty';
import { formatJSON } from './formatter/json';
import { formatSARIF } from './formatter/sarif';
import { formatDiff } from './formatter/diff';
import { formatGraphSummary } from './formatter/graph';
import { formatHTML } from './formatter/html';
import { formatFixTTY, fixSuggestionsToJSON } from './formatter/fix';
import { buildEscalationGraph } from './graph/builder';
import { extractPaths } from './graph/paths';
import { toDOT } from './graph/dot';
import { loadPolicy } from './policy/loader';
import { applyExemptions } from './policy/filter';
import { generateFixes } from './fix/llm-client';
import { isLLMAvailable } from './fix/llm-client';
import { applyFixes } from './fix/applier';
import { buildWebhookPayload, sendWebhook } from './notify/webhook';
import type { Severity } from './rules/types';
import type { FixLang } from './fix/types';
import { parseInterval, runScheduled } from './schedule/runner';
import { compareViolations } from './cluster/compare';
import { formatCompare, formatCompareJSON } from './formatter/compare';
import { RULE_MAP } from './rules/index';
import { enrichViolationsWithCIS } from './rules/cis';
import { runOPAPolicy, isOPAAvailable } from './policy/opa';

const VERSION = '0.5.0';

function printUsage(): void {
  console.log(`
rbacvet - Kubernetes RBAC security analyzer

Usage:
  rbacvet [options] [files...]

Scan Modes:
  --dir <path>              Scan all YAML files in directory recursively
  --cluster                 Analyze live cluster (uses current kubeconfig)
  --context <name>          Kubeconfig context to use (with --cluster)
  --namespace <ns>          Namespace to scan (with --cluster)
  --all-namespaces          Scan all namespaces (with --cluster)
  --diff                    Compare cluster vs local manifests
  --compare-context <ctx>       Compare violations between --context and this context

Graph Options:
  --map                     Output privilege escalation graph
  --map-format <dot|json>   Graph output format (default: dot)

Fix Suggestions:
  --fix                     Generate fix suggestions for violations
  --fix-lang <en|ja>        Language for fix explanations (default: en)
  --apply-fixes             Write auto-applicable fixes to source files
  --dry-run                 Preview --apply-fixes changes without writing

Output:
  --format <tty|json|sarif|html>  Output format (default: tty)
  --severity <level>        Minimum severity: critical, high, medium, low, info (default: info)
  --no-color                Disable colored output

Policy & Notifications:
  --policy <path>           Policy/exemption file (default: .rbacvet-policy.yaml)
  --notify <url>            POST violation summary to webhook URL (Slack-compatible)
  --schedule <interval>     Repeat scan every interval (e.g. 30s, 5m, 1h)
  --rego <file>             Apply OPA/Rego custom policy (requires opa binary)

CI/CD Integration:
  --init-ci [github|gitlab] Generate CI workflow file (default: github)
  --list-rules              List all rules with severity and CIS mapping
  --explain <rule>          Show detailed info and fix example for a rule

General:
  --ignore <rule>           Ignore rule ID (repeatable)
  --config <path>           Config file path
  -h, --help                Show this help
  -v, --version             Show version

Examples:
  rbacvet role.yaml rolebinding.yaml
  rbacvet --dir ./rbac/ --format html > report.html
  rbacvet --cluster --all-namespaces --fix
  rbacvet --cluster --diff --dir ./rbac/
  rbacvet --map --dir ./rbac/ > escalation.dot
  rbacvet --fix --fix-lang ja --dir ./rbac/
  rbacvet --format sarif --dir ./rbac/ > results.sarif
`);
}

interface CLIOptions {
  dir?: string;
  cluster: boolean;
  context?: string;
  namespace?: string;
  allNamespaces: boolean;
  diff: boolean;
  map: boolean;
  mapFormat: 'dot' | 'json';
  fix: boolean;
  fixLang: FixLang;
  applyFixes: boolean;
  dryRun: boolean;
  format: string;
  ignore: string[];
  severity: Severity;
  configPath?: string;
  policyPath?: string;
  notifyUrl?: string;
  noColor: boolean;
  files: string[];
  schedule?: string;
  compareContext?: string;
  regoFile?: string;
  initCI?: 'github' | 'gitlab';
  listRules: boolean;
  explainRule?: string;
}

function parseArgs(args: string[]): CLIOptions {
  const opts: CLIOptions = {
    cluster: false,
    allNamespaces: false,
    diff: false,
    map: false,
    mapFormat: 'dot',
    fix: false,
    fixLang: 'en',
    applyFixes: false,
    dryRun: false,
    format: 'tty',
    ignore: [],
    severity: 'info',
    noColor: false,
    files: [],
    listRules: false,
  };

  for (let i = 0; i < args.length; i++) {
    switch (args[i]) {
      case '--dir':           opts.dir = args[++i]; break;
      case '--cluster':       opts.cluster = true; break;
      case '--context':       opts.context = args[++i]; break;
      case '--namespace':     opts.namespace = args[++i]; break;
      case '--all-namespaces': opts.allNamespaces = true; break;
      case '--diff':          opts.diff = true; break;
      case '--map':           opts.map = true; break;
      case '--map-format':    opts.mapFormat = (args[++i] as 'dot' | 'json') || 'dot'; break;
      case '--fix':           opts.fix = true; break;
      case '--fix-lang':      opts.fixLang = (args[++i] as FixLang) || 'en'; break;
      case '--apply-fixes':   opts.applyFixes = true; opts.fix = true; break;
      case '--dry-run':       opts.dryRun = true; break;
      case '--format':        opts.format = args[++i] || 'tty'; break;
      case '--ignore':        opts.ignore.push(args[++i]); break;
      case '--severity':      opts.severity = (args[++i] as Severity) || 'info'; break;
      case '--config':        opts.configPath = args[++i]; break;
      case '--policy':        opts.policyPath = args[++i]; break;
      case '--notify':        opts.notifyUrl = args[++i]; break;
      case '--no-color':      opts.noColor = true; break;
      case '--schedule':      opts.schedule = args[++i]; break;
      case '--compare-context': opts.compareContext = args[++i]; break;
      case '--rego':          opts.regoFile = args[++i]; break;
      case '--init-ci':       opts.initCI = (args[i + 1] && !args[i + 1].startsWith('-') ? args[++i] : 'github') as 'github' | 'gitlab'; break;
      case '--list-rules':    opts.listRules = true; break;
      case '--explain':       opts.explainRule = args[++i]; break;
      default:
        if (!args[i].startsWith('-')) opts.files.push(args[i]);
        break;
    }
  }

  return opts;
}

function filterBySeverity(
  violations: ReturnType<typeof analyzeFiles>['violations'],
  minSeverity: Severity,
) {
  const order: Record<Severity, number> = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
  const min = order[minSeverity] ?? 0;
  return violations.filter(v => (order[v.severity] ?? 0) >= min);
}

async function runScan(
  opts: CLIOptions,
  config: ReturnType<typeof loadConfig>,
  policy: ReturnType<typeof loadPolicy>,
  useColor: boolean,
): Promise<{ hasErrors: boolean; hasWarnings: boolean; thresholdExceeded: boolean }> {
  // --- Collect resources ---
  let resources: ReturnType<typeof analyzeResources>;
  let filesCount = 0;

  if (opts.cluster) {
    const { fetchClusterResources } = await import('./cluster/fetcher');
    const clusterResources = await fetchClusterResources({
      context: opts.context, namespace: opts.namespace, allNamespaces: opts.allNamespaces,
    });
    resources = analyzeResources(clusterResources, config);
  } else {
    let files: string[] = [];
    if (opts.dir) {
      if (!fs.existsSync(opts.dir)) {
        throw new Error(`Directory not found: ${opts.dir}`);
      }
      files = collectYamlFiles(opts.dir);
    } else if (opts.files.length > 0) {
      files = opts.files;
      for (const f of files) {
        if (!fs.existsSync(f)) {
          throw new Error(`File not found: ${f}`);
        }
      }
    } else {
      throw new Error('No files specified. Use --dir, --cluster, or provide file paths.');
    }

    if (files.length === 0) {
      console.log('No YAML files found');
      return { hasErrors: false, hasWarnings: false, thresholdExceeded: false };
    }

    const result = analyzeFiles(files, config);
    resources = result;
    filesCount = files.length;

    for (const err of result.parseErrors) {
      console.error(`Parse error in ${err.file}:${err.line}: ${err.message}`);
    }
  }

  // --- Apply exemptions ---
  const allViolations = filterBySeverity(resources.violations, opts.severity);
  const filterResult = applyExemptions(allViolations, policy);

  // Warn about expired exemptions
  for (const expired of filterResult.expiredExemptions) {
    console.error(`Warning: Exemption for ${expired.rule}/${expired.resource} expired on ${expired.expires} (author: ${expired.author})`);
  }

  let violations = filterResult.remaining;

  // --- OPA/Rego policy ---
  if (opts.regoFile) {
    if (!isOPAAvailable()) {
      console.error('Warning: --rego requires the "opa" binary in PATH. Skipping OPA evaluation.');
    } else {
      try {
        const opaViolations = await runOPAPolicy(opts.regoFile, violations, resources.graph);
        violations = [...violations, ...filterBySeverity(opaViolations, opts.severity)];
      } catch (e) {
        console.error(`Warning: OPA evaluation failed: ${(e as Error).message}`);
      }
    }
  }

  // --- --map mode ---
  if (opts.map) {
    const escalationGraph = buildEscalationGraph(resources.graph);
    const paths = extractPaths(escalationGraph, resources.scores);
    if (opts.mapFormat === 'json') {
      console.log(JSON.stringify({ escalationPaths: paths, cycles: escalationGraph.cycles }, null, 2));
    } else {
      process.stderr.write(formatGraphSummary(escalationGraph, paths, useColor) + '\n');
      console.log(toDOT(escalationGraph));
    }
    return { hasErrors: false, hasWarnings: false, thresholdExceeded: false };
  }

  // --- --fix mode ---
  if (opts.fix) {
    const fixResult = await generateFixes(violations, resources.graph, {
      lang: opts.fixLang,
      useLLM: isLLMAvailable(),
    });

    if (opts.applyFixes) {
      const applyResults = await applyFixes(fixResult.suggestions, opts.dryRun);
      for (const r of applyResults) {
        if (opts.dryRun) {
          console.error(`[dry-run] ${r.file}: would apply ${r.applied} fix${r.applied !== 1 ? 'es' : ''}`);
        } else {
          console.error(`Applied ${r.applied} fix${r.applied !== 1 ? 'es' : ''} to ${r.file}`);
        }
        for (const err of r.errors) console.error(`  Error: ${err}`);
      }
    }

    if (opts.format === 'json') {
      const allResources = [...resources.graph.roles.values(), ...resources.graph.clusterRoles.values(),
        ...resources.graph.roleBindings, ...resources.graph.clusterRoleBindings, ...resources.graph.serviceAccounts.values()];
      const enrichedViolations = enrichViolationsWithCIS(violations, RULE_MAP);
      const jsonOutput = JSON.parse(formatJSON(enrichedViolations, resources.scores, filesCount, allResources));
      jsonOutput.fixes = fixSuggestionsToJSON(fixResult);
      jsonOutput.exempted = filterResult.exempted.map(e => ({ rule: e.violation.rule, resource: e.violation.resource, reason: e.exemption.reason }));
      console.log(JSON.stringify(jsonOutput, null, 2));
    } else {
      console.log(formatTTY(violations, resources.scores, useColor, RULE_MAP));
      console.log(formatFixTTY(fixResult, useColor));
    }
  } else {
    // --- Normal output ---
    switch (opts.format) {
      case 'json': {
        const allResources = [...resources.graph.roles.values(), ...resources.graph.clusterRoles.values(),
          ...resources.graph.roleBindings, ...resources.graph.clusterRoleBindings, ...resources.graph.serviceAccounts.values()];
        const enrichedViolations = enrichViolationsWithCIS(violations, RULE_MAP);
        const jsonOutput = JSON.parse(formatJSON(enrichedViolations, resources.scores, filesCount, allResources));
        if (filterResult.exempted.length > 0) {
          jsonOutput.exempted = filterResult.exempted.map(e => ({ rule: e.violation.rule, resource: e.violation.resource, reason: e.exemption.reason }));
        }
        console.log(JSON.stringify(jsonOutput, null, 2));
        break;
      }
      case 'sarif':
        console.log(formatSARIF(violations));
        break;
      case 'html': {
        const escalationGraph = buildEscalationGraph(resources.graph);
        const dotSource = toDOT(escalationGraph);
        console.log(formatHTML(violations, resources.scores, {
          filesScanned: filesCount,
          filterResult,
          dotSource,
          ruleMap: RULE_MAP,
        }));
        break;
      }
      default:
        console.log(formatTTY(violations, resources.scores, useColor, RULE_MAP));
        if (filterResult.exempted.length > 0) {
          console.log(`\n${filterResult.exempted.length} violation${filterResult.exempted.length !== 1 ? 's' : ''} exempted by policy`);
        }
        break;
    }
  }

  // --- Webhook notification ---
  const notifyUrl = opts.notifyUrl ?? config.notifyUrl;
  if (notifyUrl) {
    try {
      const payload = buildWebhookPayload(violations, resources.scores, filterResult, filesCount, VERSION);
      await sendWebhook(notifyUrl, payload);
    } catch (e) {
      console.error(`Warning: webhook notification failed: ${(e as Error).message}`);
    }
  }

  const hasErrors = violations.some(v => v.severity === 'critical' || v.severity === 'high');
  const hasWarnings = violations.some(v => v.severity === 'medium' || v.severity === 'low');
  const thresholdExceeded = resources.scores.some(s => s.score >= config.riskScoreThreshold);

  return { hasErrors, hasWarnings, thresholdExceeded };
}

function handleInitCI(platform: 'github' | 'gitlab'): void {
  if (platform === 'gitlab') {
    const content = `# .gitlab-ci.yml — RBACVet security scan
# Generated by: rbacvet --init-ci gitlab

stages:
  - security

rbacvet:
  stage: security
  image: node:20-alpine
  script:
    - npm install -g rbacvet
    - rbacvet --dir . --format sarif --severity high > rbacvet.sarif || true
    - rbacvet --dir . --severity high
  artifacts:
    when: always
    paths:
      - rbacvet.sarif
    reports:
      sast: rbacvet.sarif
  rules:
    - changes:
        - "**/*.yaml"
        - "**/*.yml"
`;
    const outPath = '.gitlab-ci.yml';
    if (fs.existsSync(outPath)) {
      console.error(`Warning: ${outPath} already exists — writing to rbacvet-ci.yml instead`);
      fs.writeFileSync('rbacvet-ci.yml', content, 'utf8');
      console.log('Generated: rbacvet-ci.yml');
    } else {
      fs.writeFileSync(outPath, content, 'utf8');
      console.log(`Generated: ${outPath}`);
    }
    return;
  }

  // GitHub Actions (default)
  const workflowDir = '.github/workflows';
  if (!fs.existsSync(workflowDir)) {
    fs.mkdirSync(workflowDir, { recursive: true });
  }
  const outPath = `${workflowDir}/rbacvet.yml`;
  const content = `# .github/workflows/rbacvet.yml — RBACVet RBAC security scan
# Generated by: rbacvet --init-ci github

name: RBACVet Security Scan

on:
  push:
    paths:
      - '**/*.yaml'
      - '**/*.yml'
  pull_request:
    paths:
      - '**/*.yaml'
      - '**/*.yml'

jobs:
  rbacvet:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write  # required for uploading SARIF

    steps:
      - uses: actions/checkout@v4

      - uses: actions/setup-node@v4
        with:
          node-version: '20'

      - name: Install rbacvet
        run: npm install -g rbacvet

      - name: Run RBAC security scan (SARIF)
        run: rbacvet --dir . --format sarif --severity high > rbacvet.sarif
        continue-on-error: true

      - name: Upload SARIF to GitHub Security tab
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: rbacvet.sarif

      - name: Fail on critical/high violations
        run: rbacvet --dir . --severity high
`;
  fs.writeFileSync(outPath, content, 'utf8');
  console.log(`Generated: ${outPath}`);
  console.log('');
  console.log('Next steps:');
  console.log('  git add .github/workflows/rbacvet.yml');
  console.log('  git commit -m "ci: add RBACVet RBAC security scan"');
}

function handleListRules(useColor: boolean): void {
  const chalk = useColor ? require('chalk') : null;
  const c = (s: string, fn: (x: string) => string) => chalk ? fn(s) : s;

  const severityColor: Record<string, (s: string) => string> = {
    critical: (s) => c(s, chalk?.red.bold ?? ((x: string) => x)),
    high:     (s) => c(s, chalk?.red ?? ((x: string) => x)),
    medium:   (s) => c(s, chalk?.yellow ?? ((x: string) => x)),
    low:      (s) => c(s, chalk?.blue ?? ((x: string) => x)),
    info:     (s) => c(s, chalk?.gray ?? ((x: string) => x)),
  };

  const { RULE_FIX_MAP } = require('./fix/rule-fixes');

  console.log('');
  console.log('RBACVet Rules:');
  console.log('─'.repeat(90));
  console.log(`${'ID'.padEnd(10)}${'SEV'.padEnd(10)}${'CIS'.padEnd(14)}${'FIX'.padEnd(6)}DESCRIPTION`);
  console.log('─'.repeat(90));

  for (const [id, rule] of RULE_MAP) {
    const sev = rule.severity.toUpperCase().padEnd(9);
    const sevStr = severityColor[rule.severity]?.(sev) ?? sev;
    const cis = (rule.cisId ?? '—').padEnd(13);
    const hasFix = RULE_FIX_MAP.has(id) ? (useColor && chalk ? chalk.green('✓') : '✓') : ' ';
    const desc = rule.description.length > 50 ? rule.description.slice(0, 47) + '...' : rule.description;
    console.log(`${id.padEnd(10)}${sevStr} ${cis} ${hasFix}    ${desc}`);
  }
  console.log('─'.repeat(90));
  console.log(`Total: ${RULE_MAP.size} rules  |  Fix available: ${RULE_FIX_MAP.size}/${RULE_MAP.size}`);
  console.log('');
}

function handleExplain(ruleId: string, useColor: boolean): void {
  const rule = RULE_MAP.get(ruleId.toUpperCase());
  if (!rule) {
    console.error(`Unknown rule: ${ruleId}`);
    console.error(`Run 'rbacvet --list-rules' to see all available rules.`);
    process.exit(1);
  }

  const { RULE_FIX_MAP } = require('./fix/rule-fixes');
  const chalk = useColor ? require('chalk') : null;
  const header = chalk ? chalk.bold : (s: string) => s;

  console.log('');
  console.log(`${header('Rule:')}        ${rule.id}`);
  console.log(`${header('Severity:')}    ${rule.severity}`);
  console.log(`${header('CIS:')}         ${rule.cisId ?? 'Not mapped'}`);
  console.log(`${header('Description:')} ${rule.description}`);
  console.log(`${header('Fix:')}         ${RULE_FIX_MAP.has(rule.id) ? 'Available (run with --fix)' : 'Not available (LLM fix may help with --fix if ANTHROPIC_API_KEY is set)'}`);
  console.log('');
}

async function main(): Promise<void> {
  const args = process.argv.slice(2);

  if (args.length === 0 || args.includes('-h') || args.includes('--help')) {
    printUsage();
    process.exit(0);
  }

  if (args.includes('-v') || args.includes('--version')) {
    console.log(`rbacvet ${VERSION}`);
    process.exit(0);
  }

  const opts = parseArgs(args);
  const config = loadConfig(opts.configPath);
  config.ignore = [...config.ignore, ...opts.ignore];

  const useColor = !opts.noColor && process.stdout.isTTY !== false;

  // --- --init-ci mode ---
  if (opts.initCI) {
    handleInitCI(opts.initCI);
    process.exit(0);
  }

  // --- --list-rules mode ---
  if (opts.listRules) {
    handleListRules(useColor);
    process.exit(0);
  }

  // --- --explain mode ---
  if (opts.explainRule) {
    handleExplain(opts.explainRule, useColor);
    process.exit(0);
  }

  // Load policy for exemptions
  const policy = loadPolicy(opts.policyPath);

  // --- --diff mode ---
  if (opts.diff) {
    if (!opts.cluster) {
      console.error('Error: --diff requires --cluster');
      process.exit(2);
    }
    if (opts.files.length === 0 && !opts.dir) {
      console.error('Error: --diff requires local files or --dir');
      process.exit(2);
    }
    const { fetchClusterResources } = await import('./cluster/fetcher');
    const { diffResources } = await import('./cluster/diff');
    const localFiles = opts.dir ? collectYamlFiles(opts.dir) : opts.files;
    const localResult = analyzeFiles(localFiles, config);
    const clusterResources = await fetchClusterResources({
      context: opts.context, namespace: opts.namespace, allNamespaces: opts.allNamespaces,
    });
    const clusterResourceList = [...clusterResources];
    const localResourceList = [
      ...localResult.graph.roles.values(), ...localResult.graph.clusterRoles.values(),
      ...localResult.graph.roleBindings, ...localResult.graph.clusterRoleBindings,
      ...localResult.graph.serviceAccounts.values(),
    ];
    const entries = diffResources(clusterResourceList, localResourceList);
    console.log(formatDiff(entries, useColor));
    process.exit(entries.length > 0 ? 1 : 0);
  }

  // --- --compare-context mode ---
  if (opts.compareContext) {
    if (!opts.cluster) {
      console.error('Error: --compare-context requires --cluster');
      process.exit(2);
    }
    const { fetchClusterResources } = await import('./cluster/fetcher');
    const contextA = opts.context ?? 'current';
    const contextB = opts.compareContext;

    const [resourcesA, resourcesB] = await Promise.all([
      fetchClusterResources({ context: opts.context, namespace: opts.namespace, allNamespaces: opts.allNamespaces }),
      fetchClusterResources({ context: contextB, namespace: opts.namespace, allNamespaces: opts.allNamespaces }),
    ]);

    const resultA = analyzeResources([...resourcesA], config);
    const resultB = analyzeResources([...resourcesB], config);

    const violationsA = filterBySeverity(resultA.violations, opts.severity);
    const violationsB = filterBySeverity(resultB.violations, opts.severity);

    const compareResult = compareViolations(violationsA, violationsB, contextA, contextB, resultA.scores, resultB.scores);

    if (opts.format === 'json') {
      console.log(formatCompareJSON(compareResult));
    } else {
      console.log(formatCompare(compareResult, useColor));
    }

    process.exit(compareResult.newCount > 0 ? 1 : 0);
  }

  // --- --schedule mode ---
  if (opts.schedule) {
    const intervalMs = parseInterval(opts.schedule);
    if (intervalMs === null) {
      console.error(`Error: Invalid schedule interval "${opts.schedule}". Use formats like 30s, 5m, 1h.`);
      process.exit(2);
    }
    console.log(`Starting scheduled scan every ${opts.schedule}`);
    await runScheduled({
      intervalMs,
      runOnce: async () => {
        await runScan(opts, config, policy, useColor);
      },
    });
    return;
  }

  // --- Single scan mode ---
  let result: { hasErrors: boolean; hasWarnings: boolean; thresholdExceeded: boolean };
  try {
    result = await runScan(opts, config, policy, useColor);
  } catch (e) {
    console.error(`Error: ${(e as Error).message}`);
    process.exit(2);
  }

  if (result.hasErrors || result.thresholdExceeded) process.exit(2);
  else if (result.hasWarnings) process.exit(1);
  else process.exit(0);
}

main().catch(err => {
  console.error(`Error: ${(err as Error).message}`);
  process.exit(2);
});
