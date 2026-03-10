import { describe, it, expect } from 'vitest';
import { extractPaths, findIndirectEscalationPaths } from '../../src/graph/paths';
import { buildEscalationGraph } from '../../src/graph/builder';
import {
  makeServiceAccount, makeClusterRole, makeClusterBinding,
  makeRole, makeBinding, analyzeResources2,
} from '../helpers';
import type { ResourceGraph } from '../../src/rules/types';

function buildGraphAndScores(...args: Parameters<typeof analyzeResources2>) {
  const result = analyzeResources2(...args);
  const egraph = buildEscalationGraph(result.graph);
  return { egraph, scores: result.scores };
}

describe('extractPaths', () => {
  it('returns empty array when no escalation paths', () => {
    const { egraph, scores } = buildGraphAndScores([
      makeServiceAccount('safe-sa', 'default', false),
      makeRole('pod-reader', [{ apiGroups: [''], resources: ['pods'], verbs: ['get'] }]),
      makeBinding('safe-sa', 'pod-reader', 'default'),
    ]);
    const paths = extractPaths(egraph, scores);
    expect(paths).toHaveLength(0);
  });

  it('returns path for SA bound to cluster-admin', () => {
    const { egraph, scores } = buildGraphAndScores([
      makeServiceAccount('admin-sa', 'default', false),
      makeClusterBinding('admin-sa', 'cluster-admin', 'default'),
    ]);
    const paths = extractPaths(egraph, scores);
    expect(paths.length).toBeGreaterThan(0);
    expect(paths[0].serviceAccount.name).toBe('admin-sa');
  });

  it('marks direct cluster-admin path as endsAtClusterAdmin', () => {
    const { egraph, scores } = buildGraphAndScores([
      makeServiceAccount('admin-sa', 'default', false),
      makeClusterBinding('admin-sa', 'cluster-admin', 'default'),
    ]);
    const paths = extractPaths(egraph, scores);
    expect(paths[0].endsAtClusterAdmin).toBe(true);
  });

  it('includes score when scores are provided', () => {
    const { egraph, scores } = buildGraphAndScores([
      makeServiceAccount('admin-sa', 'default', false),
      makeClusterBinding('admin-sa', 'cluster-admin', 'default'),
    ]);
    const paths = extractPaths(egraph, scores);
    expect(paths[0].score).toBeDefined();
    expect(paths[0].score).toBeGreaterThan(0);
  });

  it('sorts paths by score descending', () => {
    const { egraph, scores } = buildGraphAndScores([
      makeServiceAccount('high-sa', 'default', false),
      makeServiceAccount('low-sa', 'default', false),
      makeClusterBinding('high-sa', 'cluster-admin', 'default'),
      makeClusterRole('minimal-priv-role', [{ apiGroups: [''], resources: ['pods'], verbs: ['*'] }]),
      makeClusterBinding('low-sa', 'minimal-priv-role', 'default'),
    ]);
    const paths = extractPaths(egraph, scores);
    for (let i = 1; i < paths.length; i++) {
      expect((paths[i - 1].score ?? 0)).toBeGreaterThanOrEqual(paths[i].score ?? 0);
    }
  });

  it('path nodes include kind, name, namespace', () => {
    const { egraph, scores } = buildGraphAndScores([
      makeServiceAccount('admin-sa', 'default', false),
      makeClusterBinding('admin-sa', 'cluster-admin', 'default'),
    ]);
    const paths = extractPaths(egraph, scores);
    const path = paths[0];
    expect(path.path.length).toBeGreaterThan(1);
    for (const node of path.path) {
      expect(node).toHaveProperty('kind');
      expect(node).toHaveProperty('name');
    }
  });

  it('includes riskLevel when scores provided', () => {
    const { egraph, scores } = buildGraphAndScores([
      makeServiceAccount('admin-sa', 'default', false),
      makeClusterBinding('admin-sa', 'cluster-admin', 'default'),
    ]);
    const paths = extractPaths(egraph, scores);
    expect(paths[0].riskLevel).toBeDefined();
    expect(['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']).toContain(paths[0].riskLevel);
  });
});

describe('findIndirectEscalationPaths', () => {
  function buildGraph(resources: ReturnType<typeof makeServiceAccount | typeof makeRole | typeof makeBinding>[]): ResourceGraph {
    return analyzeResources2(resources as Parameters<typeof analyzeResources2>[0]).graph;
  }

  it('returns a path for SA bound to role with rolebinding write access', () => {
    const graph = buildGraph([
      makeServiceAccount('binding-editor', 'default', false),
      makeRole('rb-writer', [{ apiGroups: ['rbac.authorization.k8s.io'], resources: ['rolebindings'], verbs: ['create', 'update', 'patch'] }]),
      makeBinding('binding-editor', 'rb-writer', 'default'),
    ]);
    const paths = findIndirectEscalationPaths(graph);
    expect(paths.length).toBeGreaterThan(0);
    const path = paths.find(p => p.serviceAccount.includes('binding-editor'));
    expect(path).toBeDefined();
    expect(path!.riskLevel).toBe('HIGH');
    expect(path!.path.some(s => s.includes('indirect escalation'))).toBe(true);
  });

  it('returns empty for SA with only read access', () => {
    const graph = buildGraph([
      makeServiceAccount('reader-sa', 'default', false),
      makeRole('rb-reader', [{ apiGroups: ['rbac.authorization.k8s.io'], resources: ['rolebindings'], verbs: ['get', 'list', 'watch'] }]),
      makeBinding('reader-sa', 'rb-reader', 'default'),
    ]);
    const paths = findIndirectEscalationPaths(graph);
    const match = paths.find(p => p.serviceAccount.includes('reader-sa'));
    expect(match).toBeUndefined();
  });
});
