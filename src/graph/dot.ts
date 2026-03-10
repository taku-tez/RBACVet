import type { EscalationGraph, GraphNode } from './builder';

function escapeId(id: string): string {
  return `"${id.replace(/"/g, '\\"')}"`;
}

function nodeAttrs(node: GraphNode): string {
  const attrs: string[] = [];

  switch (node.kind) {
    case 'ServiceAccount':
      attrs.push('shape=ellipse');
      attrs.push('style=filled');
      attrs.push('fillcolor=lightblue');
      break;
    case 'RoleBinding':
    case 'ClusterRoleBinding':
      attrs.push('shape=diamond');
      attrs.push('style=filled');
      attrs.push('fillcolor=lightyellow');
      break;
    case 'Role':
    case 'ClusterRole':
      attrs.push('shape=box');
      break;
  }

  if (node.isClusterAdmin) {
    attrs.push('style=filled');
    attrs.push('fillcolor=red');
    attrs.push('fontcolor=white');
    attrs.push('penwidth=2');
  } else if (node.isClusterAdminEquivalent) {
    attrs.push('style=filled');
    attrs.push('fillcolor=orange');
  }

  const ns = node.namespace ? `\\n(${node.namespace})` : '';
  attrs.push(`label=${escapeId(`${node.name}${ns}`)}`);

  return `[${attrs.join(', ')}]`;
}

export function toDOT(graph: EscalationGraph): string {
  const lines: string[] = [];
  lines.push('digraph rbacvet {');
  lines.push('  rankdir=LR;');
  lines.push('  node [fontname="Helvetica" fontsize=10];');
  lines.push('  edge [fontname="Helvetica" fontsize=9];');
  lines.push('');

  // Group nodes by kind
  const groups: Record<string, GraphNode[]> = {
    ServiceAccount: [],
    RoleBinding: [],
    ClusterRoleBinding: [],
    Role: [],
    ClusterRole: [],
  };
  for (const node of graph.nodes.values()) {
    groups[node.kind]?.push(node);
  }

  const clusterLabels: Record<string, string> = {
    ServiceAccount: 'ServiceAccounts',
    RoleBinding: 'RoleBindings',
    ClusterRoleBinding: 'ClusterRoleBindings',
    Role: 'Roles',
    ClusterRole: 'ClusterRoles',
  };
  const clusterColors: Record<string, string> = {
    ServiceAccount: 'aliceblue',
    RoleBinding: 'lightyellow',
    ClusterRoleBinding: 'lemonchiffon',
    Role: 'honeydew',
    ClusterRole: 'mintcream',
  };

  let clusterIndex = 0;
  for (const [kind, kindNodes] of Object.entries(groups)) {
    if (kindNodes.length === 0) continue;
    lines.push(`  subgraph cluster_${clusterIndex++} {`);
    lines.push(`    label="${clusterLabels[kind] ?? kind}";`);
    lines.push(`    style=filled; color="${clusterColors[kind] ?? 'white'}";`);
    for (const node of kindNodes) {
      lines.push(`    ${escapeId(node.id)} ${nodeAttrs(node)};`);
    }
    lines.push('  }');
    lines.push('');
  }

  // Edges
  // Track which edges are on escalation paths
  const escalationEdgeSet = new Set<string>();
  for (const path of graph.escalationPaths) {
    for (let i = 0; i < path.length - 1; i++) {
      escalationEdgeSet.add(`${path[i]}->${path[i + 1]}`);
    }
  }

  for (const edge of graph.edges) {
    const isEscalation = escalationEdgeSet.has(`${edge.from}->${edge.to}`) || edge.isEscalation;
    const attrs: string[] = [`label="${edge.label}"`];
    if (isEscalation) {
      attrs.push('color=red');
      attrs.push('penwidth=2');
      attrs.push('fontcolor=red');
    }
    lines.push(`  ${escapeId(edge.from)} -> ${escapeId(edge.to)} [${attrs.join(', ')}];`);
  }

  // Cycle edges (orange dashed)
  for (const cycle of graph.cycles) {
    for (let i = 0; i < cycle.length; i++) {
      const from = cycle[i];
      const to = cycle[(i + 1) % cycle.length];
      lines.push(`  ${escapeId(from)} -> ${escapeId(to)} [color=orange, style=dashed, label="cycle"];`);
    }
  }

  lines.push('}');
  return lines.join('\n');
}
