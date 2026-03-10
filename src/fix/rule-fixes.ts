import * as yaml from 'js-yaml';
import type { Violation, ResourceGraph } from '../rules/types';
import type { Role, PolicyRule } from '../parser/types';
import type { FixSuggestion, FixLang } from './types';
import { WRITE_VERBS } from '../rules/utils';

type RuleFixFn = (
  violation: Violation,
  graph: ResourceGraph,
  lang: FixLang,
) => FixSuggestion | null;

function findRole(resource: string, graph: ResourceGraph): Role | undefined {
  // resource is like "ClusterRole/name" or "Role/ns/name" or "Role/name"
  const parts = resource.split('/');
  const kind = parts[0];
  const name = parts[parts.length - 1];
  const ns = parts.length === 3 ? parts[1] : parts.length === 2 ? undefined : undefined;

  if (kind === 'ClusterRole') return graph.clusterRoles.get(name);
  if (kind === 'Role') {
    if (ns) return graph.roles.get(`${ns}/${name}`);
    // Search by name if ns unknown
    for (const [key, role] of graph.roles) {
      if (role.metadata.name === name) return role;
    }
  }
  return undefined;
}

function patchRules(rules: PolicyRule[], patcher: (r: PolicyRule) => PolicyRule): string {
  const patched = rules.map(patcher);
  return yaml.dump({ rules: patched }, { lineWidth: -1, indent: 2 }).trim();
}

const EXPLANATIONS: Record<string, Record<FixLang, string>> = {
  RB1001: {
    en: 'Replace wildcard verb "*" with specific read-only verbs. If write access is needed, explicitly enumerate: create, update, patch, delete.',
    ja: 'ワイルドカード動詞 "*" を特定の読み取り専用動詞に置き換えてください。書き込みアクセスが必要な場合は、create, update, patch, delete を明示的に列挙してください。',
  },
  RB1002: {
    en: 'Replace wildcard resource "*" with only the specific resources this workload requires. Avoid granting access to resources like secrets, nodes, or namespaces unless explicitly needed.',
    ja: 'ワイルドカードリソース "*" を、このワークロードが必要とする特定のリソースのみに置き換えてください。secrets, nodes, namespaces などのリソースへのアクセスは、明示的に必要な場合以外は避けてください。',
  },
  RB2001: {
    en: 'Remove the cluster-admin binding. Create a dedicated ClusterRole with only the minimum required permissions and rebind to it.',
    ja: 'cluster-admin バインディングを削除してください。必要最小限のパーミッションを持つ専用の ClusterRole を作成し、それにバインドし直してください。',
  },
  RB3001: {
    en: 'Restrict secret access to specific named secrets using resourceNames. Remove "list" and "watch" verbs unless the workload needs to enumerate secrets.',
    ja: 'resourceNames を使用して特定のシークレットへのアクセスを制限してください。ワークロードがシークレットを列挙する必要がない限り、"list" と "watch" 動詞を削除してください。',
  },
  RB3002: {
    en: 'Remove write access to secrets. If you must write secrets, restrict to specific named secrets via resourceNames and remove delete/deletecollection.',
    ja: 'シークレットへの書き込みアクセスを削除してください。シークレットへの書き込みが必要な場合は、resourceNames で特定のシークレットに制限し、delete/deletecollection を削除してください。',
  },
  RB4001: {
    en: 'Add automountServiceAccountToken: false to disable automatic token mounting. Mount the token explicitly in pods that need it using a projected volume.',
    ja: 'automountServiceAccountToken: false を追加して、トークンの自動マウントを無効にしてください。トークンが必要な Pod では、projected ボリュームを使って明示的にマウントしてください。',
  },
};

const RB1001Fix: RuleFixFn = (violation, graph, lang) => {
  const role = findRole(violation.resource, graph);
  if (!role) return null;

  const patch = patchRules(role.rules, (r) => ({
    ...r,
    verbs: r.verbs.includes('*') ? ['get', 'list', 'watch'] : r.verbs,
  }));

  return {
    violation,
    ruleId: 'RB1001',
    source: 'rule-based',
    explanation: EXPLANATIONS.RB1001[lang],
    yamlPatch: patch,
    autoApplicable: true,
    patchTarget: { file: violation.file, startLine: violation.line, endLine: violation.line + 30 },
  };
};

const RB1002Fix: RuleFixFn = (violation, graph, lang) => {
  const role = findRole(violation.resource, graph);
  if (!role) return null;

  const patch = patchRules(role.rules, (r) => ({
    ...r,
    resources: r.resources.includes('*') ? ['pods'] : r.resources,
  }));

  return {
    violation,
    ruleId: 'RB1002',
    source: 'rule-based',
    explanation: EXPLANATIONS.RB1002[lang],
    yamlPatch: `# TODO: replace 'pods' with the actual resources this workload requires\n${patch}`,
    autoApplicable: false,
    patchTarget: { file: violation.file, startLine: violation.line, endLine: violation.line + 30 },
  };
};

const RB2001Fix: RuleFixFn = (violation, graph, lang) => {
  const parts = violation.resource.split('/');
  const bindingName = parts[parts.length - 1];
  const restrictedName = `${bindingName.replace('-binding', '')}-restricted`;

  const suggestedRole = `apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: ${restrictedName}
rules:
  [] # TODO: add only the permissions this workload requires`;

  const suggestedBinding = `apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: ${bindingName}
subjects: # keep existing subjects
roleRef:
  kind: ClusterRole
  name: ${restrictedName}
  apiGroup: rbac.authorization.k8s.io`;

  return {
    violation,
    ruleId: 'RB2001',
    source: 'rule-based',
    explanation: EXPLANATIONS.RB2001[lang],
    yamlPatch: `${suggestedRole}\n---\n${suggestedBinding}`,
    autoApplicable: false,
    patchTarget: { file: violation.file, startLine: violation.line, endLine: violation.line + 10 },
  };
};

const RB3001Fix: RuleFixFn = (violation, graph, lang) => {
  const role = findRole(violation.resource, graph);
  if (!role) return null;

  const patch = patchRules(role.rules, (r) => {
    if (!r.resources.includes('secrets') && !r.resources.includes('*')) return r;
    return {
      ...r,
      verbs: r.verbs.filter(v => v !== 'list' && v !== 'watch' && v !== '*'),
      resourceNames: r.resourceNames ?? ['# TODO: list specific secret names here'],
    };
  });

  return {
    violation,
    ruleId: 'RB3001',
    source: 'rule-based',
    explanation: EXPLANATIONS.RB3001[lang],
    yamlPatch: patch,
    autoApplicable: false,
    patchTarget: { file: violation.file, startLine: violation.line, endLine: violation.line + 30 },
  };
};

const RB3002Fix: RuleFixFn = (violation, graph, lang) => {
  const role = findRole(violation.resource, graph);
  if (!role) return null;

  const allWriteVerbs = [...WRITE_VERBS, '*'];
  const patch = patchRules(role.rules, (r) => {
    if (!r.resources.includes('secrets') && !r.resources.includes('*')) return r;
    return {
      ...r,
      verbs: r.verbs.filter(v => !allWriteVerbs.includes(v)),
      resourceNames: r.resourceNames ?? ['# TODO: specify secret names if read access is required'],
    };
  });

  return {
    violation,
    ruleId: 'RB3002',
    source: 'rule-based',
    explanation: EXPLANATIONS.RB3002[lang],
    yamlPatch: patch,
    autoApplicable: false,
    patchTarget: { file: violation.file, startLine: violation.line, endLine: violation.line + 30 },
  };
};

const RB4001Fix: RuleFixFn = (violation, graph, lang) => {
  const saName = violation.resource.replace('ServiceAccount/', '').split('/').pop() ?? '';
  const patch = `automountServiceAccountToken: false`;

  return {
    violation,
    ruleId: 'RB4001',
    source: 'rule-based',
    explanation: EXPLANATIONS.RB4001[lang],
    yamlPatch: patch,
    autoApplicable: true,
    patchTarget: { file: violation.file, startLine: violation.line, endLine: violation.line + 5 },
  };
};

export const RULE_FIX_MAP = new Map<string, RuleFixFn>([
  ['RB1001', RB1001Fix],
  ['RB1002', RB1002Fix],
  ['RB2001', RB2001Fix],
  ['RB3001', RB3001Fix],
  ['RB3002', RB3002Fix],
  ['RB4001', RB4001Fix],
]);

RULE_FIX_MAP.set('IS1001', (violation, _graph, lang) => {
  const name = violation.resource.split('/').pop() ?? 'policy';
  const ns = violation.resource.split('/')[1] ?? 'default';
  const yamlPatch = `spec:
  action: ALLOW
  rules:
  - from:
    - source:
        principals:
        - cluster.local/ns/${ns}/sa/your-service-account
    to:
    - operation:
        methods: ["GET"]`;
  return {
    violation,
    ruleId: 'IS1001',
    source: 'rule-based',
    explanation: lang === 'ja'
      ? 'AuthorizationPolicyのALLOWルールに制限を追加してください。全トラフィックを許可するポリシーは危険です。'
      : 'Add source restrictions to this ALLOW AuthorizationPolicy. An ALLOW policy with no rules permits all traffic to the matched workload.',
    yamlPatch,
    autoApplicable: false,
    patchTarget: { file: violation.file, startLine: violation.line, endLine: violation.line + 5 },
  };
});

export function generateRuleFixes(
  violations: Violation[],
  graph: ResourceGraph,
  lang: FixLang,
): FixSuggestion[] {
  const suggestions: FixSuggestion[] = [];
  const seen = new Set<string>();

  for (const v of violations) {
    const key = `${v.rule}:${v.resource}`;
    if (seen.has(key)) continue;
    seen.add(key);

    const fixFn = RULE_FIX_MAP.get(v.rule);
    if (!fixFn) continue;

    const suggestion = fixFn(v, graph, lang);
    if (suggestion) suggestions.push(suggestion);
  }

  return suggestions;
}
