import { describe, it, expect } from 'vitest';
import { buildEscalationGraph, detectCycles } from '../../src/graph/builder';
import { makeRole, makeClusterRole, makeBinding, makeClusterBinding, makeServiceAccount, analyzeResources2 } from '../helpers';
import type { GraphNode, GraphEdge } from '../../src/graph/builder';

function buildGraphFromResources(...args: Parameters<typeof analyzeResources2>) {
  const { graph } = analyzeResources2(...args);
  return buildEscalationGraph(graph);
}

describe('buildEscalationGraph', () => {
  it('creates ServiceAccount nodes', () => {
    const egraph = buildGraphFromResources([
      makeServiceAccount('my-sa', 'default', false),
    ]);
    const saNodes = [...egraph.nodes.values()].filter(n => n.kind === 'ServiceAccount');
    expect(saNodes.some(n => n.name === 'my-sa')).toBe(true);
  });

  it('creates Role nodes', () => {
    const egraph = buildGraphFromResources([
      makeRole('pod-reader', [{ apiGroups: [''], resources: ['pods'], verbs: ['get'] }]),
    ]);
    const roleNodes = [...egraph.nodes.values()].filter(n => n.kind === 'Role' || n.kind === 'ClusterRole');
    expect(roleNodes.some(n => n.name === 'pod-reader')).toBe(true);
  });

  it('creates edges from SA to binding to role', () => {
    const egraph = buildGraphFromResources([
      makeServiceAccount('app-sa', 'default', false),
      makeRole('pod-reader', [{ apiGroups: [''], resources: ['pods'], verbs: ['get'] }]),
      makeBinding('app-sa', 'pod-reader', 'default'),
    ]);
    expect(egraph.edges.length).toBeGreaterThan(0);
    // SA should connect to binding
    const saId = 'SA:default/app-sa';
    const saEdges = egraph.edges.filter(e => e.from === saId);
    expect(saEdges.length).toBeGreaterThan(0);
  });

  it('detects escalation path for SA bound to cluster-admin', () => {
    const egraph = buildGraphFromResources([
      makeServiceAccount('admin-sa', 'default', false),
      makeClusterBinding('admin-sa', 'cluster-admin', 'default'),
    ]);
    expect(egraph.escalationPaths.length).toBeGreaterThan(0);
    const adminPath = egraph.escalationPaths.find(p =>
      p.some(id => id.includes('admin-sa'))
    );
    expect(adminPath).toBeDefined();
  });

  it('detects escalation path for SA bound to wildcard ClusterRole', () => {
    const egraph = buildGraphFromResources([
      makeServiceAccount('power-sa', 'default', false),
      makeClusterRole('super-admin', [{ apiGroups: ['*'], resources: ['*'], verbs: ['*'] }]),
      makeClusterBinding('power-sa', 'super-admin', 'default'),
    ]);
    expect(egraph.escalationPaths.length).toBeGreaterThan(0);
  });

  it('no escalation paths for minimal-permission SA', () => {
    const egraph = buildGraphFromResources([
      makeServiceAccount('safe-sa', 'default', false),
      makeRole('pod-reader', [{ apiGroups: [''], resources: ['pods'], verbs: ['get'] }]),
      makeBinding('safe-sa', 'pod-reader', 'default'),
    ]);
    expect(egraph.escalationPaths).toHaveLength(0);
  });

  it('marks cluster-admin node as isClusterAdmin', () => {
    const egraph = buildGraphFromResources([
      makeServiceAccount('admin-sa', 'default', false),
      makeClusterBinding('admin-sa', 'cluster-admin', 'default'),
    ]);
    const caNode = [...egraph.nodes.values()].find(n => n.name === 'cluster-admin');
    expect(caNode?.isClusterAdmin).toBe(true);
    expect(caNode?.isClusterAdminEquivalent).toBe(true);
  });

  it('marks wildcard ClusterRole as isClusterAdminEquivalent', () => {
    const egraph = buildGraphFromResources([
      makeClusterRole('all-access', [{ apiGroups: ['*'], resources: ['*'], verbs: ['*'] }]),
    ]);
    const node = [...egraph.nodes.values()].find(n => n.name === 'all-access');
    expect(node?.isClusterAdminEquivalent).toBe(true);
  });

  it('returns empty cycles for acyclic graph', () => {
    const egraph = buildGraphFromResources([
      makeServiceAccount('safe-sa', 'default', false),
      makeRole('pod-reader', [{ apiGroups: [''], resources: ['pods'], verbs: ['get'] }]),
      makeBinding('safe-sa', 'pod-reader', 'default'),
    ]);
    expect(egraph.cycles).toHaveLength(0);
  });
});

describe('detectCycles', () => {
  it('detects a simple cycle A → B → A', () => {
    const nodes = new Map<string, GraphNode>([
      ['A', { id: 'A', kind: 'Role', name: 'A', isClusterAdminEquivalent: false, isClusterAdmin: false }],
      ['B', { id: 'B', kind: 'Role', name: 'B', isClusterAdminEquivalent: false, isClusterAdmin: false }],
    ]);
    const edges: GraphEdge[] = [
      { from: 'A', to: 'B', label: 'test', isEscalation: false },
      { from: 'B', to: 'A', label: 'test', isEscalation: false },
    ];
    const cycles = detectCycles(nodes, edges);
    expect(cycles.length).toBeGreaterThan(0);
  });

  it('returns empty for acyclic graph', () => {
    const nodes = new Map<string, GraphNode>([
      ['A', { id: 'A', kind: 'Role', name: 'A', isClusterAdminEquivalent: false, isClusterAdmin: false }],
      ['B', { id: 'B', kind: 'Role', name: 'B', isClusterAdminEquivalent: false, isClusterAdmin: false }],
      ['C', { id: 'C', kind: 'Role', name: 'C', isClusterAdminEquivalent: false, isClusterAdmin: false }],
    ]);
    const edges: GraphEdge[] = [
      { from: 'A', to: 'B', label: 'test', isEscalation: false },
      { from: 'B', to: 'C', label: 'test', isEscalation: false },
    ];
    const cycles = detectCycles(nodes, edges);
    expect(cycles).toHaveLength(0);
  });

  it('detects 3-node cycle A → B → C → A', () => {
    const nodes = new Map<string, GraphNode>([
      ['A', { id: 'A', kind: 'Role', name: 'A', isClusterAdminEquivalent: false, isClusterAdmin: false }],
      ['B', { id: 'B', kind: 'Role', name: 'B', isClusterAdminEquivalent: false, isClusterAdmin: false }],
      ['C', { id: 'C', kind: 'Role', name: 'C', isClusterAdminEquivalent: false, isClusterAdmin: false }],
    ]);
    const edges: GraphEdge[] = [
      { from: 'A', to: 'B', label: 'x', isEscalation: false },
      { from: 'B', to: 'C', label: 'x', isEscalation: false },
      { from: 'C', to: 'A', label: 'x', isEscalation: false },
    ];
    const cycles = detectCycles(nodes, edges);
    expect(cycles.length).toBeGreaterThan(0);
  });
});
