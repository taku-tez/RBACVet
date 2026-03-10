import { describe, it, expect } from 'vitest';
import { toDOT } from '../../src/graph/dot';
import { buildEscalationGraph } from '../../src/graph/builder';
import { makeServiceAccount, makeClusterRole, makeClusterBinding, analyzeResources2 } from '../helpers';

function buildGraph(...args: Parameters<typeof analyzeResources2>) {
  const { graph } = analyzeResources2(...args);
  return buildEscalationGraph(graph);
}

describe('toDOT', () => {
  it('produces valid DOT header', () => {
    const egraph = buildGraph([
      makeServiceAccount('my-sa', 'default', false),
    ]);
    const dot = toDOT(egraph);
    expect(dot).toContain('digraph rbacvet');
    expect(dot).toContain('rankdir=LR');
  });

  it('closes digraph block', () => {
    const egraph = buildGraph([
      makeServiceAccount('my-sa', 'default', false),
    ]);
    const dot = toDOT(egraph);
    expect(dot.trim()).toMatch(/\}$/);
  });

  it('includes SA node in output', () => {
    const egraph = buildGraph([
      makeServiceAccount('my-sa', 'default', false),
    ]);
    const dot = toDOT(egraph);
    expect(dot).toContain('my-sa');
  });

  it('uses red color for cluster-admin node', () => {
    const egraph = buildGraph([
      makeServiceAccount('admin-sa', 'default', false),
      makeClusterBinding('admin-sa', 'cluster-admin', 'default'),
    ]);
    const dot = toDOT(egraph);
    expect(dot).toContain('cluster-admin');
    expect(dot).toContain('fillcolor=red');
  });

  it('produces edge arrows with ->', () => {
    const egraph = buildGraph([
      makeServiceAccount('admin-sa', 'default', false),
      makeClusterBinding('admin-sa', 'cluster-admin', 'default'),
    ]);
    const dot = toDOT(egraph);
    expect(dot).toContain('->');
  });

  it('marks escalation edges with red color', () => {
    const egraph = buildGraph([
      makeServiceAccount('admin-sa', 'default', false),
      makeClusterBinding('admin-sa', 'cluster-admin', 'default'),
    ]);
    const dot = toDOT(egraph);
    // Escalation edges should have color=red
    expect(dot).toContain('color=red');
  });

  it('includes subgraph cluster sections', () => {
    const egraph = buildGraph([
      makeServiceAccount('my-sa', 'default', false),
      makeClusterRole('my-role', [{ apiGroups: [''], resources: ['pods'], verbs: ['get'] }]),
      makeClusterBinding('my-sa', 'my-role', 'default'),
    ]);
    const dot = toDOT(egraph);
    expect(dot).toContain('subgraph cluster_');
  });

  it('handles empty graph without crashing', () => {
    const egraph = buildGraph([]);
    const dot = toDOT(egraph);
    expect(dot).toContain('digraph rbacvet');
  });
});
