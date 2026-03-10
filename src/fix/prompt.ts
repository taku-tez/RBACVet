import type { Violation } from '../rules/types';
import type { FixLang } from './types';

export function buildSystemPrompt(lang: FixLang): string {
  if (lang === 'ja') {
    return `あなたは Kubernetes RBAC セキュリティの専門家です。rbacvet が検出した RBAC 違反に対して、最小権限の原則に基づいた修正を提案することが役割です。

出力形式 — 必ず以下の形式で応答してください：

\`\`\`yaml
<修正後の rules: ブロックのみ>
\`\`\`

説明: <短い段落での説明（日本語で）>

ルール:
- 元のリソースに存在しないパーミッションを追加しないこと
- 既存のパーミッションの削除または制限のみを行うこと
- metadata（name, namespace, labels, annotations）はそのまま保持すること
- 最小パーミッションが判断できない場合は、resourceNames による制限を提案すること`;
  }

  return `You are a Kubernetes RBAC security expert. Your task is to suggest minimal least-privilege fixes for RBAC violations detected by rbacvet.

Output format — respond with ONLY the following structure:

\`\`\`yaml
<replacement rules: block only>
\`\`\`

Explanation: <one short paragraph>

Rules:
- Do not add permissions not present in the original
- Only remove or restrict existing permissions
- Preserve all metadata (name, namespace, labels, annotations)
- If minimal permissions cannot be determined, suggest adding resourceNames restrictions instead`;
}

export function buildUserPrompt(
  violation: Violation,
  roleYaml: string,
  context: string,
  lang: FixLang,
): string {
  return `Violation: [${violation.rule}] ${violation.message}
File: ${violation.file}:${violation.line}
Resource: ${violation.resource}

Current YAML:
\`\`\`yaml
${roleYaml}
\`\`\`

Binding context: ${context}

${lang === 'ja' ? '最小権限の修正を提案してください。' : 'Suggest a minimal fix.'}`;
}

export function parseYamlFromResponse(response: string): { yaml: string; explanation: string } {
  const yamlMatch = response.match(/```ya?ml\n([\s\S]*?)```/);
  const yaml = yamlMatch ? yamlMatch[1].trim() : '';

  const explanationMatch = response.match(/(?:Explanation:|説明:)\s*([\s\S]*?)$/m);
  const explanation = explanationMatch ? explanationMatch[1].trim() : response.replace(/```[\s\S]*?```/g, '').trim();

  return { yaml, explanation };
}
