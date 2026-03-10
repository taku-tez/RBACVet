import type { ResourceGraph } from '../rules/types';
import type { RoleBinding } from '../parser/types';
import { isClusterAdminEquivalent, makeRoleKey } from '../rules/utils';

export type NodeKind = 'ServiceAccount' | 'RoleBinding' | 'ClusterRoleBinding' | 'Role' | 'ClusterRole';

export interface GraphNode {
  id: string;
  kind: NodeKind;
  name: string;
  namespace?: string;
  isClusterAdminEquivalent: boolean;
  isClusterAdmin: boolean;
}

export interface GraphEdge {
  from: string;
  to: string;
  label: string;
  isEscalation: boolean;
}

export interface EscalationGraph {
  nodes: Map<string, GraphNode>;
  edges: GraphEdge[];
  escalationPaths: string[][];
  cycles: string[][];
}

function saNodeId(name: string, ns: string): string {
  return `SA:${ns}/${name}`;
}

function bindingNodeId(b: RoleBinding): string {
  const ns = b.metadata.namespace ? `${b.metadata.namespace}/` : '';
  return `${b.kind}:${ns}${b.metadata.name}`;
}

function roleNodeId(kind: string, name: string): string {
  return `${kind}:${name}`;
}

export function buildEscalationGraph(graph: ResourceGraph): EscalationGraph {
  const nodes = new Map<string, GraphNode>();
  const edges: GraphEdge[] = [];

  // Add ServiceAccount nodes
  for (const sa of graph.serviceAccounts.values()) {
    const ns = sa.metadata.namespace ?? 'default';
    const id = saNodeId(sa.metadata.name, ns);
    nodes.set(id, {
      id,
      kind: 'ServiceAccount',
      name: sa.metadata.name,
      namespace: ns,
      isClusterAdminEquivalent: false,
      isClusterAdmin: false,
    });
  }

  // Add Role nodes
  for (const role of graph.roles.values()) {
    const id = roleNodeId(role.kind, role.metadata.name);
    nodes.set(id, {
      id,
      kind: role.kind as NodeKind,
      name: role.metadata.name,
      namespace: role.metadata.namespace,
      isClusterAdminEquivalent: isClusterAdminEquivalent(role),
      isClusterAdmin: false,
    });
  }

  // Add ClusterRole nodes
  for (const role of graph.clusterRoles.values()) {
    const id = roleNodeId(role.kind, role.metadata.name);
    const isAdmin = role.metadata.name === 'cluster-admin';
    nodes.set(id, {
      id,
      kind: 'ClusterRole',
      name: role.metadata.name,
      namespace: undefined,
      isClusterAdminEquivalent: isAdmin || isClusterAdminEquivalent(role),
      isClusterAdmin: isAdmin,
    });
  }

  // Ensure cluster-admin node exists even if not in graph
  const clusterAdminId = roleNodeId('ClusterRole', 'cluster-admin');
  if (!nodes.has(clusterAdminId)) {
    nodes.set(clusterAdminId, {
      id: clusterAdminId,
      kind: 'ClusterRole',
      name: 'cluster-admin',
      namespace: undefined,
      isClusterAdminEquivalent: true,
      isClusterAdmin: true,
    });
  }

  // Add Binding nodes and edges
  const allBindings = [...graph.roleBindings, ...graph.clusterRoleBindings];
  for (const binding of allBindings) {
    const bindingId = bindingNodeId(binding);

    // Resolve the target role
    let targetRoleId: string;
    if (binding.roleRef.kind === 'ClusterRole') {
      targetRoleId = roleNodeId('ClusterRole', binding.roleRef.name);
    } else {
      const ns = binding.metadata.namespace;
      const key = makeRoleKey(binding.roleRef.name, ns);
      const role = graph.roles.get(key);
      targetRoleId = role ? roleNodeId('Role', role.metadata.name) : roleNodeId('Role', binding.roleRef.name);
    }

    const targetNode = nodes.get(targetRoleId);
    const isEscalation = targetNode?.isClusterAdminEquivalent ?? binding.roleRef.name === 'cluster-admin';

    // Only add binding node if it has SA subjects
    const saSubjects = binding.subjects.filter(s => s.kind === 'ServiceAccount');
    if (saSubjects.length === 0) continue;

    if (!nodes.has(bindingId)) {
      nodes.set(bindingId, {
        id: bindingId,
        kind: binding.kind as NodeKind,
        name: binding.metadata.name,
        namespace: binding.metadata.namespace,
        isClusterAdminEquivalent: false,
        isClusterAdmin: false,
      });
    }

    // Ensure target role node exists
    if (!nodes.has(targetRoleId)) {
      nodes.set(targetRoleId, {
        id: targetRoleId,
        kind: binding.roleRef.kind as NodeKind,
        name: binding.roleRef.name,
        namespace: undefined,
        isClusterAdminEquivalent: binding.roleRef.name === 'cluster-admin',
        isClusterAdmin: binding.roleRef.name === 'cluster-admin',
      });
    }

    // SA → Binding edges
    for (const subject of saSubjects) {
      const ns = subject.namespace ?? 'default';
      const saId = saNodeId(subject.name, ns);
      if (!nodes.has(saId)) {
        nodes.set(saId, {
          id: saId,
          kind: 'ServiceAccount',
          name: subject.name,
          namespace: ns,
          isClusterAdminEquivalent: false,
          isClusterAdmin: false,
        });
      }
      edges.push({
        from: saId,
        to: bindingId,
        label: 'bound via',
        isEscalation,
      });
    }

    // Binding → Role edge
    edges.push({
      from: bindingId,
      to: targetRoleId,
      label: 'references',
      isEscalation,
    });
  }

  // Find escalation paths (SA → ... → cluster-admin-equivalent)
  const escalationPaths = findEscalationPaths(nodes, edges);
  const cycles = detectCycles(nodes, edges);

  return { nodes, edges, escalationPaths, cycles };
}

function findEscalationPaths(
  nodes: Map<string, GraphNode>,
  edges: GraphEdge[],
): string[][] {
  const paths: string[][] = [];
  const adjacency = new Map<string, string[]>();
  for (const edge of edges) {
    const targets = adjacency.get(edge.from) ?? [];
    targets.push(edge.to);
    adjacency.set(edge.from, targets);
  }

  for (const [id, node] of nodes) {
    if (node.kind !== 'ServiceAccount') continue;

    const path: string[] = [id];
    const visited = new Set<string>([id]);

    function dfs(current: string): boolean {
      const targets = adjacency.get(current) ?? [];
      for (const next of targets) {
        if (visited.has(next)) continue;
        const nextNode = nodes.get(next);
        if (!nextNode) continue;

        path.push(next);
        visited.add(next);

        if (nextNode.isClusterAdminEquivalent) {
          paths.push([...path]);
          path.pop();
          visited.delete(next);
          return true;
        }

        dfs(next);
        path.pop();
        visited.delete(next);
      }
      return false;
    }

    dfs(id);
  }

  return paths;
}

export function detectCycles(
  nodes: Map<string, GraphNode>,
  edges: GraphEdge[],
): string[][] {
  const adjacency = new Map<string, string[]>();
  for (const edge of edges) {
    const targets = adjacency.get(edge.from) ?? [];
    targets.push(edge.to);
    adjacency.set(edge.from, targets);
  }

  const WHITE = 0, GRAY = 1, BLACK = 2;
  const color = new Map<string, number>();
  for (const id of nodes.keys()) color.set(id, WHITE);

  const cycles: string[][] = [];
  const stack: string[] = [];

  function dfs(node: string): void {
    color.set(node, GRAY);
    stack.push(node);

    for (const next of adjacency.get(node) ?? []) {
      if (color.get(next) === GRAY) {
        // Found a cycle — extract it from the stack
        const cycleStart = stack.indexOf(next);
        cycles.push(stack.slice(cycleStart));
      } else if (color.get(next) === WHITE) {
        dfs(next);
      }
    }

    stack.pop();
    color.set(node, BLACK);
  }

  for (const id of nodes.keys()) {
    if (color.get(id) === WHITE) dfs(id);
  }

  return cycles;
}
