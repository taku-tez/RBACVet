import type { Violation, ResourceGraph } from '../rules/types';
import type { FixSuggestion, FixLang, FixResult } from './types';
import type { Role } from '../parser/types';
import { generateRuleFixes } from './rule-fixes';
import { buildSystemPrompt, buildUserPrompt, parseYamlFromResponse } from './prompt';
import * as yaml from 'js-yaml';

export function isLLMAvailable(): boolean {
  return !!process.env.ANTHROPIC_API_KEY;
}

function getRoleYaml(violation: Violation, graph: ResourceGraph): string {
  const parts = violation.resource.split('/');
  const kind = parts[0];
  const name = parts[parts.length - 1];
  const ns = parts.length === 3 ? parts[1] : undefined;

  let role: Role | undefined;
  if (kind === 'ClusterRole') {
    role = graph.clusterRoles.get(name);
  } else if (kind === 'Role') {
    if (ns) {
      role = graph.roles.get(`${ns}/${name}`);
    } else {
      for (const r of graph.roles.values()) {
        if (r.metadata.name === name) { role = r; break; }
      }
    }
  }

  if (!role) return '';
  return yaml.dump({
    apiVersion: role.apiVersion,
    kind: role.kind,
    metadata: role.metadata,
    rules: role.rules,
  }, { lineWidth: -1 });
}

function getBindingContext(violation: Violation, graph: ResourceGraph): string {
  const parts = violation.resource.split('/');
  const name = parts[parts.length - 1];

  const bindings = [...graph.roleBindings, ...graph.clusterRoleBindings]
    .filter(b => b.roleRef.name === name)
    .map(b => {
      const saSubjects = b.subjects
        .filter(s => s.kind === 'ServiceAccount')
        .map(s => `ServiceAccount/${s.namespace ?? 'default'}/${s.name}`);
      return `${b.kind}/${b.metadata.name} → [${saSubjects.join(', ')}]`;
    });

  return bindings.length > 0 ? bindings.join('; ') : 'No bindings found in scanned resources';
}

export async function generateLLMFixes(
  violations: Violation[],
  graph: ResourceGraph,
  lang: FixLang,
): Promise<FixSuggestion[]> {
  if (!isLLMAvailable()) return [];

  const { default: Anthropic } = await import('@anthropic-ai/sdk');
  const client = new Anthropic();

  const suggestions: FixSuggestion[] = [];
  const seen = new Set<string>();
  const fixableRules = new Set(['RB1001', 'RB1002', 'RB2001', 'RB3001', 'RB3002', 'RB4001']);

  for (const violation of violations) {
    const key = `${violation.rule}:${violation.resource}`;
    if (seen.has(key)) continue;
    if (!fixableRules.has(violation.rule)) continue;
    seen.add(key);

    const roleYaml = getRoleYaml(violation, graph);
    if (!roleYaml && violation.rule !== 'RB4001') continue;

    const context = getBindingContext(violation, graph);

    try {
      const response = await client.messages.create({
        model: 'claude-haiku-4-5',
        max_tokens: 1024,
        system: buildSystemPrompt(lang),
        messages: [{
          role: 'user',
          content: buildUserPrompt(violation, roleYaml, context, lang),
        }],
      });

      const content = response.content[0];
      if (content.type !== 'text') continue;

      const { yaml: yamlPatch, explanation } = parseYamlFromResponse(content.text);
      if (!yamlPatch) continue;

      suggestions.push({
        violation,
        ruleId: violation.rule,
        source: 'llm',
        explanation,
        yamlPatch,
        autoApplicable: false,
        patchTarget: {
          file: violation.file,
          startLine: violation.line,
          endLine: violation.line + 30,
        },
      });
    } catch {
      // Fall through to rule-based fix if LLM fails
    }
  }

  return suggestions;
}

export async function generateFixes(
  violations: Violation[],
  graph: ResourceGraph,
  opts: { lang: FixLang; useLLM: boolean },
): Promise<FixResult> {
  const errors: FixResult['errors'] = [];

  // Always generate rule-based fixes
  const ruleBasedSuggestions = generateRuleFixes(violations, graph, opts.lang);

  let llmSuggestions: FixSuggestion[] = [];
  let llmUsed = false;

  if (opts.useLLM && isLLMAvailable()) {
    try {
      llmSuggestions = await generateLLMFixes(violations, graph, opts.lang);
      llmUsed = llmSuggestions.length > 0;
    } catch (e) {
      errors.push({ ruleId: 'LLM', message: (e as Error).message });
    }
  }

  // Prefer LLM suggestions over rule-based when available for the same rule+resource
  const llmKeys = new Set(llmSuggestions.map(s => `${s.ruleId}:${s.violation.resource}`));
  const merged = [
    ...llmSuggestions,
    ...ruleBasedSuggestions.filter(s => !llmKeys.has(`${s.ruleId}:${s.violation.resource}`)),
  ];

  return { suggestions: merged, llmUsed, errors };
}
