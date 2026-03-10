import type { ResourceGraph } from '../rules/types';
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
export declare function buildEscalationGraph(graph: ResourceGraph): EscalationGraph;
export declare function detectCycles(nodes: Map<string, GraphNode>, edges: GraphEdge[]): string[][];
