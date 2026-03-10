"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.diffResources = diffResources;
function resourceKey(r) {
    const ns = r.metadata.namespace ?? '';
    return `${r.kind}/${ns}/${r.metadata.name}`;
}
function sortedRules(rules) {
    return [...rules].sort((a, b) => JSON.stringify(a).localeCompare(JSON.stringify(b)));
}
function sortedSubjects(subjects) {
    return [...subjects].sort((a, b) => `${a.kind}/${a.namespace}/${a.name}`.localeCompare(`${b.kind}/${b.namespace}/${b.name}`));
}
function semanticHash(r) {
    if (r.kind === 'Role' || r.kind === 'ClusterRole') {
        const role = r;
        return JSON.stringify(sortedRules(role.rules));
    }
    if (r.kind === 'RoleBinding' || r.kind === 'ClusterRoleBinding') {
        const binding = r;
        return JSON.stringify({
            subjects: sortedSubjects(binding.subjects),
            roleRef: binding.roleRef,
        });
    }
    if (r.kind === 'ServiceAccount') {
        const sa = r;
        return JSON.stringify({ automountServiceAccountToken: sa.automountServiceAccountToken });
    }
    return JSON.stringify(r);
}
function computeChanges(cluster, local) {
    const changes = [];
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
function diffResources(clusterResources, localResources) {
    const clusterMap = new Map();
    const localMap = new Map();
    for (const r of clusterResources)
        clusterMap.set(resourceKey(r), r);
    for (const r of localResources)
        localMap.set(resourceKey(r), r);
    const entries = [];
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
        }
        else {
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
//# sourceMappingURL=diff.js.map