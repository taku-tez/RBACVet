import type { ResourceGraph } from '../rules/types';
import type { Violation } from '../rules/types';
import { findEscalationChain } from '../rules/rb2/privilege-escalation';

export type RiskLevel = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';

export interface ServiceAccountScore {
  name: string;
  score: number;
  level: RiskLevel;
  reasons: string[];
  escalationPath?: string[];
}

export interface ScoringResult {
  scores: ServiceAccountScore[];
  maxScore: number;
  exceededThreshold: boolean;
}

function riskLevel(score: number): RiskLevel {
  if (score >= 80) return 'CRITICAL';
  if (score >= 60) return 'HIGH';
  if (score >= 30) return 'MEDIUM';
  return 'LOW';
}

export function computeScores(
  graph: ResourceGraph,
  violations: Violation[],
  threshold: number,
  trusted: string[],
): ScoringResult {
  const scores: ServiceAccountScore[] = [];
  const trustedSet = new Set(trusted);

  const violationsBySA = new Map<string, Violation[]>();
  for (const v of violations) {
    if (v.resource.startsWith('ServiceAccount/')) {
      const existing = violationsBySA.get(v.resource) || [];
      existing.push(v);
      violationsBySA.set(v.resource, existing);
    }
  }

  for (const sa of graph.serviceAccounts.values()) {
    const ns = sa.metadata.namespace || 'default';
    const saKey = `ServiceAccount/${ns}/${sa.metadata.name}`;
    let score = 0;
    const reasons: string[] = [];

    // automountServiceAccountToken
    if (sa.automountServiceAccountToken !== false) {
      score += 10;
      reasons.push('automountServiceAccountToken enabled (+10)');
    }

    // Check bound roles for broad permissions
    const allBindings = [...graph.roleBindings, ...graph.clusterRoleBindings];
    const boundBindings = allBindings.filter(b =>
      b.subjects.some(s =>
        s.kind === 'ServiceAccount' && s.name === sa.metadata.name &&
        (s.namespace === ns || b.kind === 'ClusterRoleBinding')
      )
    );

    for (const binding of boundBindings) {
      let role = binding.roleRef.kind === 'ClusterRole'
        ? graph.clusterRoles.get(binding.roleRef.name)
        : graph.roles.get(`${binding.metadata.namespace || ns}/${binding.roleRef.name}`);

      if (!role) continue;

      const hasBroadVerbs = role.rules.some(r => r.verbs.includes('*'));
      const hasBroadResources = role.rules.some(r => r.resources.includes('*'));

      if (hasBroadVerbs || hasBroadResources) {
        score += 30;
        reasons.push(`bound to ${role.kind}/${role.metadata.name} with wildcard permissions (+30)`);
        break;
      }

      // secrets read
      const hasSecretsRead = role.rules.some(r =>
        (r.resources.includes('secrets') || r.resources.includes('*')) &&
        (r.verbs.includes('get') || r.verbs.includes('list') || r.verbs.includes('*'))
      );
      if (hasSecretsRead) {
        score += 15;
        reasons.push(`bound role can read secrets (+15)`);
      }

      // pods/exec
      const hasExec = role.rules.some(r =>
        r.resources.includes('pods/exec') || r.resources.includes('*')
      );
      if (hasExec) {
        score += 20;
        reasons.push(`bound role can exec into pods (+20)`);
      }
    }

    // Escalation chain check
    const chain = findEscalationChain(sa.metadata.name, ns, graph, trustedSet);
    if (chain) {
      // Direct cluster-admin binding: chain is [saKey, 'ClusterRole/cluster-admin']
      const isDirectClusterAdmin = chain.length === 2 && chain[1] === 'ClusterRole/cluster-admin';
      if (isDirectClusterAdmin) {
        score += 80;
        reasons.push(`direct cluster-admin binding (+80)`);
      } else {
        score += 40;
        reasons.push(`privilege escalation path to cluster-admin-equivalent role (+40)`);
      }
    }

    score = Math.min(score, 100);

    scores.push({
      name: saKey,
      score,
      level: riskLevel(score),
      reasons,
      escalationPath: chain ?? undefined,
    });
  }

  scores.sort((a, b) => b.score - a.score);
  const maxScore = scores.length > 0 ? scores[0].score : 0;

  return {
    scores,
    maxScore,
    exceededThreshold: maxScore >= threshold,
  };
}
