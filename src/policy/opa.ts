import { execFile } from 'child_process';
import { promisify } from 'util';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import type { Violation, ResourceGraph } from '../rules/types';

const execFileAsync = promisify(execFile);

export interface OPAViolation {
  rule: string;
  severity: string;
  message: string;
  resource: string;
  file?: string;
  line?: number;
}

export interface OPAInput {
  violations: Violation[];
  graph: {
    roles: Array<{ name: string; namespace?: string; rules: unknown[] }>;
    clusterRoles: Array<{ name: string; rules: unknown[] }>;
    roleBindings: Array<{ name: string; namespace?: string; subjects: unknown[]; roleRef: unknown }>;
    clusterRoleBindings: Array<{ name: string; subjects: unknown[]; roleRef: unknown }>;
    serviceAccounts: Array<{ name: string; namespace?: string; automountServiceAccountToken?: boolean }>;
  };
}

export function isOPAAvailable(): boolean {
  try {
    require('child_process').execFileSync('opa', ['version'], { stdio: 'pipe' });
    return true;
  } catch {
    return false;
  }
}

function buildOPAInput(violations: Violation[], graph: ResourceGraph): OPAInput {
  return {
    violations,
    graph: {
      roles: [...graph.roles.values()].map(r => ({
        name: r.metadata.name,
        namespace: r.metadata.namespace,
        rules: r.rules,
      })),
      clusterRoles: [...graph.clusterRoles.values()].map(r => ({
        name: r.metadata.name,
        rules: r.rules,
      })),
      roleBindings: graph.roleBindings.map(rb => ({
        name: rb.metadata.name,
        namespace: rb.metadata.namespace,
        subjects: rb.subjects,
        roleRef: rb.roleRef,
      })),
      clusterRoleBindings: graph.clusterRoleBindings.map(rb => ({
        name: rb.metadata.name,
        subjects: rb.subjects,
        roleRef: rb.roleRef,
      })),
      serviceAccounts: [...graph.serviceAccounts.values()].map(sa => ({
        name: sa.metadata.name,
        namespace: sa.metadata.namespace,
        automountServiceAccountToken: sa.automountServiceAccountToken,
      })),
    },
  };
}

function parseOPAResult(stdout: string): OPAViolation[] {
  try {
    const parsed = JSON.parse(stdout);
    // OPA eval returns: { "result": [{ "expressions": [{ "value": ... }] }] }
    const value = parsed?.result?.[0]?.expressions?.[0]?.value;
    if (!Array.isArray(value)) return [];
    return value.filter((v: unknown) => {
      const item = v as Record<string, unknown>;
      return typeof item.rule === 'string' && typeof item.message === 'string';
    }).map((v: unknown) => {
      const item = v as Record<string, unknown>;
      return {
        rule: item.rule as string,
        severity: (item.severity as string) ?? 'warning',
        message: item.message as string,
        resource: (item.resource as string) ?? 'unknown',
        file: item.file as string | undefined,
        line: item.line as number | undefined,
      };
    });
  } catch {
    return [];
  }
}

export async function runOPAPolicy(
  regoFile: string,
  violations: Violation[],
  graph: ResourceGraph,
): Promise<Violation[]> {
  if (!fs.existsSync(regoFile)) {
    throw new Error(`Rego policy file not found: ${regoFile}`);
  }

  const input = buildOPAInput(violations, graph);
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'rbacvet-'));
  const inputFile = path.join(tmpDir, 'input.json');

  try {
    fs.writeFileSync(inputFile, JSON.stringify(input));
    const { stdout } = await execFileAsync('opa', [
      'eval',
      '--format', 'json',
      '--data', regoFile,
      '--input', inputFile,
      'data.rbacvet.violations',
    ]);

    const opaViolations = parseOPAResult(stdout);
    return opaViolations.map(v => ({
      rule: v.rule,
      severity: (['error', 'warning', 'info'].includes(v.severity) ? v.severity : 'warning') as Violation['severity'],
      message: v.message,
      resource: v.resource,
      file: v.file ?? regoFile,
      line: v.line ?? 0,
    }));
  } finally {
    try { fs.unlinkSync(inputFile); } catch { /* ignore */ }
    try { fs.rmdirSync(tmpDir); } catch { /* ignore */ }
  }
}
