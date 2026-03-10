import type { EscalationGraph, GraphNode } from './builder';
import type { ServiceAccountScore } from '../engine/scorer';
import type { ResourceGraph } from '../rules/types';

export interface PathNode {
  kind: string;
  name: string;
  namespace?: string;
}

export interface EscalationPath {
  serviceAccount: { name: string; namespace: string };
  path: PathNode[];
  endsAtClusterAdmin: boolean;
  score?: number;
  riskLevel?: string;
}

export interface IndirectEscalationPath {
  serviceAccount: string;
  path: string[];
  riskLevel: 'CRITICAL' | 'HIGH' | 'MEDIUM';
}

/**
 * Detects ServiceAccounts that can modify RoleBindings/ClusterRoleBindings,
 * enabling them to add themselves to high-privilege bindings (2-hop escalation).
 */
export function findIndirectEscalationPaths(graph: ResourceGraph): IndirectEscalationPath[] {
  const paths: IndirectEscalationPath[] = [];
  const allBindings = [...graph.roleBindings, ...graph.clusterRoleBindings];

  for (const binding of allBindings) {
    const saSubjects = binding.subjects.filter(s => s.kind === 'ServiceAccount');
    if (saSubjects.length === 0) continue;

    const role = binding.roleRef.kind === 'ClusterRole'
      ? graph.clusterRoles.get(binding.roleRef.name)
      : graph.roles.get(
          binding.metadata.namespace
            ? `${binding.metadata.namespace}/${binding.roleRef.name}`
            : binding.roleRef.name,
        );
    if (!role) continue;

    const canModifyBindings = role.rules.some(r => {
      const targetsBindings =
        r.resources.includes('rolebindings') ||
        r.resources.includes('clusterrolebindings') ||
        r.resources.includes('*');
      const hasWrite = ['create', 'update', 'patch', 'delete', '*'].some(v => r.verbs.includes(v));
      return targetsBindings && hasWrite;
    });

    if (!canModifyBindings) continue;

    for (const subject of saSubjects) {
      const saName = subject.namespace
        ? `${subject.namespace}/${subject.name}`
        : subject.name;
      paths.push({
        serviceAccount: saName,
        path: [
          `ServiceAccount/${saName}`,
          `${binding.kind}/${binding.metadata.name}`,
          `${role.kind}/${role.metadata.name}`,
          '→ can modify RoleBindings (indirect escalation)',
        ],
        riskLevel: 'HIGH',
      });
    }
  }

  return paths;
}

function parseNodeId(id: string, nodes: Map<string, GraphNode>): PathNode | null {
  const node = nodes.get(id);
  if (!node) return null;
  return { kind: node.kind, name: node.name, namespace: node.namespace };
}

export function extractPaths(
  graph: EscalationGraph,
  scores?: ServiceAccountScore[],
): EscalationPath[] {
  const scoreMap = new Map<string, ServiceAccountScore>();
  if (scores) {
    for (const s of scores) scoreMap.set(s.name, s);
  }

  const paths: EscalationPath[] = [];

  for (const rawPath of graph.escalationPaths) {
    if (rawPath.length < 2) continue;

    const saNodeId = rawPath[0];
    const saNode = graph.nodes.get(saNodeId);
    if (!saNode || saNode.kind !== 'ServiceAccount') continue;

    const lastNode = graph.nodes.get(rawPath[rawPath.length - 1]);
    const endsAtClusterAdmin = lastNode?.isClusterAdminEquivalent ?? false;

    const pathNodes: PathNode[] = rawPath
      .map(id => parseNodeId(id, graph.nodes))
      .filter((n): n is PathNode => n !== null);

    const saScoreKey = `ServiceAccount/${saNode.namespace ?? 'default'}/${saNode.name}`;
    const saScore = scoreMap.get(saScoreKey);

    paths.push({
      serviceAccount: {
        name: saNode.name,
        namespace: saNode.namespace ?? 'default',
      },
      path: pathNodes,
      endsAtClusterAdmin,
      score: saScore?.score,
      riskLevel: saScore?.level,
    });
  }

  // Sort by score descending
  paths.sort((a, b) => (b.score ?? 0) - (a.score ?? 0));

  return paths;
}
