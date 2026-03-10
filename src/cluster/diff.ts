import type { K8sResource, Role, RoleBinding, ServiceAccount, PolicyRule, Subject } from '../parser/types';

export type DiffStatus = 'added' | 'removed' | 'changed';

export interface FieldChange {
  field: string;
  clusterValue: unknown;
  localValue: unknown;
}

export interface DiffEntry {
  status: DiffStatus;
  kind: string;
  name: string;
  namespace?: string;
  clusterResource?: K8sResource;
  localResource?: K8sResource;
  changes?: FieldChange[];
}

function resourceKey(r: K8sResource): string {
  const ns = r.metadata.namespace ?? '';
  return `${r.kind}/${ns}/${r.metadata.name}`;
}

function sortedRules(rules: PolicyRule[]): PolicyRule[] {
  return [...rules].sort((a, b) => JSON.stringify(a).localeCompare(JSON.stringify(b)));
}

function sortedSubjects(subjects: Subject[]): Subject[] {
  return [...subjects].sort((a, b) =>
    `${a.kind}/${a.namespace}/${a.name}`.localeCompare(`${b.kind}/${b.namespace}/${b.name}`)
  );
}

function semanticHash(r: K8sResource): string {
  if (r.kind === 'Role' || r.kind === 'ClusterRole') {
    const role = r as Role;
    return JSON.stringify(sortedRules(role.rules));
  }
  if (r.kind === 'RoleBinding' || r.kind === 'ClusterRoleBinding') {
    const binding = r as RoleBinding;
    return JSON.stringify({
      subjects: sortedSubjects(binding.subjects),
      roleRef: binding.roleRef,
    });
  }
  if (r.kind === 'ServiceAccount') {
    const sa = r as ServiceAccount;
    return JSON.stringify({ automountServiceAccountToken: sa.automountServiceAccountToken });
  }
  return JSON.stringify(r);
}

function computeChanges(cluster: K8sResource, local: K8sResource): FieldChange[] {
  const changes: FieldChange[] = [];
  const ch = semanticHash(cluster);
  const lh = semanticHash(local);
  if (ch !== lh) {
    changes.push({
      field: 'spec',
      clusterValue: JSON.parse(ch),
      localValue: JSON.parse(lh),
    });
  }
  return changes;
}

export function diffResources(
  clusterResources: K8sResource[],
  localResources: K8sResource[],
): DiffEntry[] {
  const clusterMap = new Map<string, K8sResource>();
  const localMap = new Map<string, K8sResource>();

  for (const r of clusterResources) clusterMap.set(resourceKey(r), r);
  for (const r of localResources) localMap.set(resourceKey(r), r);

  const entries: DiffEntry[] = [];

  for (const [key, cr] of clusterMap) {
    const lr = localMap.get(key);
    if (!lr) {
      entries.push({
        status: 'removed',
        kind: cr.kind,
        name: cr.metadata.name,
        namespace: cr.metadata.namespace,
        clusterResource: cr,
      });
    } else {
      const changes = computeChanges(cr, lr);
      if (changes.length > 0) {
        entries.push({
          status: 'changed',
          kind: cr.kind,
          name: cr.metadata.name,
          namespace: cr.metadata.namespace,
          clusterResource: cr,
          localResource: lr,
          changes,
        });
      }
    }
  }

  for (const [key, lr] of localMap) {
    if (!clusterMap.has(key)) {
      entries.push({
        status: 'added',
        kind: lr.kind,
        name: lr.metadata.name,
        namespace: lr.metadata.namespace,
        localResource: lr,
      });
    }
  }

  entries.sort((a, b) => `${a.kind}/${a.namespace}/${a.name}`.localeCompare(`${b.kind}/${b.namespace}/${b.name}`));
  return entries;
}
