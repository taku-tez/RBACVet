import * as yaml from 'js-yaml';
import {
  K8sResource, Role, RoleBinding, ServiceAccount, AuthorizationPolicy,
  PolicyRule, Subject, RoleRef, ParseResult, ParseError,
  IstioRule,
} from './types';

function getLineNumber(content: string, offset: number): number {
  return content.slice(0, offset).split('\n').length;
}

function buildPolicyRules(raw: unknown): PolicyRule[] {
  if (!Array.isArray(raw)) return [];
  return raw.map((r: unknown) => {
    const rule = r as Record<string, unknown>;
    return {
      apiGroups: Array.isArray(rule.apiGroups) ? rule.apiGroups as string[] : [],
      resources: Array.isArray(rule.resources) ? rule.resources as string[] : [],
      verbs: Array.isArray(rule.verbs) ? rule.verbs as string[] : [],
      resourceNames: Array.isArray(rule.resourceNames) ? rule.resourceNames as string[] : undefined,
    };
  });
}

function buildSubjects(raw: unknown): Subject[] {
  if (!Array.isArray(raw)) return [];
  return raw.map((s: unknown) => {
    const subj = s as Record<string, unknown>;
    return {
      kind: (subj.kind as Subject['kind']) || 'ServiceAccount',
      name: (subj.name as string) || '',
      namespace: subj.namespace as string | undefined,
    };
  });
}

function buildRoleRef(raw: unknown): RoleRef {
  const ref = (raw as Record<string, unknown>) || {};
  return {
    kind: (ref.kind as RoleRef['kind']) || 'Role',
    name: (ref.name as string) || '',
    apiGroup: (ref.apiGroup as string) || 'rbac.authorization.k8s.io',
  };
}

function buildMeta(raw: unknown): { name: string; namespace?: string; annotations?: Record<string, string>; labels?: Record<string, string> } {
  const m = (raw as Record<string, unknown>) || {};
  return {
    name: (m.name as string) || '',
    namespace: m.namespace as string | undefined,
    annotations: m.annotations as Record<string, string> | undefined,
    labels: m.labels as Record<string, string> | undefined,
  };
}

export function parseFile(content: string, filePath: string): ParseResult {
  const resources: K8sResource[] = [];
  const errors: ParseError[] = [];

  // Split on --- to track approximate line numbers per document
  const docSeparatorRegex = /^---[ \t]*$/m;
  const docStarts: number[] = [0];
  let match: RegExpExecArray | null;
  const sepRegex = /^---[ \t]*$/gm;
  while ((match = sepRegex.exec(content)) !== null) {
    docStarts.push(match.index + match[0].length + 1);
  }

  let docIndex = 0;
  try {
    yaml.loadAll(content, (doc) => {
      if (doc === null || doc === undefined) {
        docIndex++;
        return;
      }

      const startOffset = docStarts[docIndex] ?? 0;
      const sourceLine = getLineNumber(content, startOffset);
      docIndex++;

      const raw = doc as Record<string, unknown>;
      const kind = raw.kind as string;
      const apiVersion = (raw.apiVersion as string) || '';
      const metadata = buildMeta(raw.metadata);

      if (!metadata.name) return;

      try {
        switch (kind) {
          case 'Role':
          case 'ClusterRole': {
            const role: Role = {
              kind: kind as 'Role' | 'ClusterRole',
              apiVersion,
              metadata,
              rules: buildPolicyRules(raw.rules),
              sourceFile: filePath,
              sourceLine,
            };
            resources.push(role);
            break;
          }
          case 'RoleBinding':
          case 'ClusterRoleBinding': {
            const binding: RoleBinding = {
              kind: kind as 'RoleBinding' | 'ClusterRoleBinding',
              apiVersion,
              metadata,
              subjects: buildSubjects(raw.subjects),
              roleRef: buildRoleRef(raw.roleRef),
              sourceFile: filePath,
              sourceLine,
            };
            resources.push(binding);
            break;
          }
          case 'ServiceAccount': {
            const sa: ServiceAccount = {
              kind: 'ServiceAccount',
              apiVersion,
              metadata,
              automountServiceAccountToken: raw.automountServiceAccountToken as boolean | undefined,
              sourceFile: filePath,
              sourceLine,
            };
            resources.push(sa);
            break;
          }
          case 'AuthorizationPolicy': {
            const spec = (raw.spec as Record<string, unknown>) || {};
            const rawRules = Array.isArray(spec.rules) ? spec.rules as unknown[] : undefined;
            const istioRules: IstioRule[] | undefined = rawRules?.map((r) => {
              const ir = r as Record<string, unknown>;
              return {
                from: Array.isArray(ir.from) ? (ir.from as Array<Record<string, unknown>>).map(f => ({
                  source: (f.source as Record<string, unknown>) ?? {},
                })) : undefined,
                to: Array.isArray(ir.to) ? (ir.to as Array<Record<string, unknown>>).map(t => ({
                  operation: (t.operation as Record<string, unknown>) ?? {},
                })) : undefined,
              };
            });
            const policy: AuthorizationPolicy = {
              kind: 'AuthorizationPolicy',
              apiVersion,
              metadata,
              spec: {
                action: spec.action as AuthorizationPolicy['spec']['action'],
                rules: istioRules,
                selector: spec.selector as AuthorizationPolicy['spec']['selector'],
              },
              sourceFile: filePath,
              sourceLine,
            };
            resources.push(policy);
            break;
          }
          // Unknown kinds are silently skipped
        }
      } catch (e) {
        errors.push({
          file: filePath,
          line: sourceLine,
          message: (e as Error).message,
        });
      }
    });
  } catch (e) {
    const yamlErr = e as yaml.YAMLException;
    errors.push({
      file: filePath,
      line: yamlErr.mark?.line ?? 0,
      message: yamlErr.message,
    });
  }

  return { resources, errors };
}

export function parseFiles(files: { path: string; content: string }[]): ParseResult {
  const allResources: K8sResource[] = [];
  const allErrors: ParseError[] = [];

  for (const f of files) {
    const result = parseFile(f.content, f.path);
    allResources.push(...result.resources);
    allErrors.push(...result.errors);
  }

  return { resources: allResources, errors: allErrors };
}
