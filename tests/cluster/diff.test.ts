import { describe, it, expect } from 'vitest';
import { diffResources } from '../../src/cluster/diff';
import { makeRole, makeClusterRole, makeBinding, makeClusterBinding, makeServiceAccount } from '../helpers';
import type { K8sResource } from '../../src/parser/types';

describe('diffResources', () => {
  it('returns empty array when both sets are identical', () => {
    const resources = [
      makeRole('pod-reader', [{ apiGroups: [''], resources: ['pods'], verbs: ['get'] }]),
    ];
    const entries = diffResources(resources, resources);
    expect(entries).toHaveLength(0);
  });

  it('detects resource only in cluster (removed from local)', () => {
    const clusterResources = [
      makeRole('cluster-only-role', [{ apiGroups: [''], resources: ['pods'], verbs: ['get'] }]),
    ];
    const localResources: K8sResource[] = [];
    const entries = diffResources(clusterResources, localResources);
    expect(entries).toHaveLength(1);
    expect(entries[0].status).toBe('removed');
    expect(entries[0].name).toBe('cluster-only-role');
  });

  it('detects resource only in local (added in local)', () => {
    const clusterResources: K8sResource[] = [];
    const localResources = [
      makeRole('local-only-role', [{ apiGroups: [''], resources: ['pods'], verbs: ['get'] }]),
    ];
    const entries = diffResources(clusterResources, localResources);
    expect(entries).toHaveLength(1);
    expect(entries[0].status).toBe('added');
    expect(entries[0].name).toBe('local-only-role');
  });

  it('detects changed Role (different verbs)', () => {
    const clusterRole = makeRole('my-role', [{ apiGroups: [''], resources: ['pods'], verbs: ['get'] }]);
    const localRole = makeRole('my-role', [{ apiGroups: [''], resources: ['pods'], verbs: ['get', 'list'] }]);
    clusterRole.sourceFile = '<cluster>';
    const entries = diffResources([clusterRole], [localRole]);
    expect(entries).toHaveLength(1);
    expect(entries[0].status).toBe('changed');
  });

  it('ignores sourceFile and sourceLine in comparison', () => {
    const clusterRole = makeRole('same-role', [{ apiGroups: [''], resources: ['pods'], verbs: ['get'] }]);
    const localRole = makeRole('same-role', [{ apiGroups: [''], resources: ['pods'], verbs: ['get'] }]);
    clusterRole.sourceFile = '<cluster>';
    clusterRole.sourceLine = 0;
    localRole.sourceFile = '/path/to/role.yaml';
    localRole.sourceLine = 5;
    const entries = diffResources([clusterRole], [localRole]);
    expect(entries).toHaveLength(0);
  });

  it('detects changed RoleBinding (different subjects)', () => {
    const clusterBinding = makeBinding('sa-a', 'my-role', 'default');
    clusterBinding.sourceFile = '<cluster>';
    const localBinding = makeBinding('sa-b', 'my-role', 'default');
    localBinding.metadata.name = clusterBinding.metadata.name;
    const entries = diffResources([clusterBinding], [localBinding]);
    expect(entries).toHaveLength(1);
    expect(entries[0].status).toBe('changed');
  });

  it('detects changed ServiceAccount (automount changed)', () => {
    const clusterSA = makeServiceAccount('my-sa', 'default', true);
    clusterSA.sourceFile = '<cluster>';
    const localSA = makeServiceAccount('my-sa', 'default', false);
    const entries = diffResources([clusterSA], [localSA]);
    expect(entries).toHaveLength(1);
    expect(entries[0].status).toBe('changed');
  });

  it('handles multiple resources with mixed statuses', () => {
    const clusterResources = [
      makeRole('shared-role', [{ apiGroups: [''], resources: ['pods'], verbs: ['get'] }]),
      makeRole('cluster-only', [{ apiGroups: [''], resources: ['nodes'], verbs: ['get'] }]),
    ];
    const localResources = [
      makeRole('shared-role', [{ apiGroups: [''], resources: ['pods'], verbs: ['get'] }]),
      makeRole('local-only', [{ apiGroups: [''], resources: ['secrets'], verbs: ['get'] }]),
    ];
    clusterResources.forEach(r => r.sourceFile = '<cluster>');
    const entries = diffResources(clusterResources, localResources);
    expect(entries).toHaveLength(2); // cluster-only (removed) + local-only (added)
    const statuses = entries.map(e => e.status).sort();
    expect(statuses).toEqual(['added', 'removed']);
  });

  it('identifies resource by kind+namespace+name', () => {
    const roleInNsA = makeRole('my-role', [{ apiGroups: [''], resources: ['pods'], verbs: ['get'] }], 'ns-a');
    const roleInNsB = makeRole('my-role', [{ apiGroups: [''], resources: ['pods'], verbs: ['get'] }], 'ns-b');
    roleInNsA.sourceFile = '<cluster>';
    const entries = diffResources([roleInNsA], [roleInNsB]);
    expect(entries).toHaveLength(2);
  });

  it('includes FieldChange detail for changed resources', () => {
    const clusterRole = makeRole('changed-role', [{ apiGroups: [''], resources: ['pods'], verbs: ['get'] }]);
    const localRole = makeRole('changed-role', [{ apiGroups: [''], resources: ['pods'], verbs: ['get', 'list'] }]);
    clusterRole.sourceFile = '<cluster>';
    const entries = diffResources([clusterRole], [localRole]);
    expect(entries[0].changes).toBeDefined();
    expect(entries[0].changes!.length).toBeGreaterThan(0);
  });
});
