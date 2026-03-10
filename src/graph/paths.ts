import type { EscalationGraph, GraphNode } from './builder';
import type { ServiceAccountScore } from '../engine/scorer';

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
