"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.CLUSTER_SOURCE = void 0;
exports.convertRole = convertRole;
exports.convertClusterRole = convertClusterRole;
exports.convertRoleBinding = convertRoleBinding;
exports.convertClusterRoleBinding = convertClusterRoleBinding;
exports.convertServiceAccount = convertServiceAccount;
exports.CLUSTER_SOURCE = '<cluster>';
function convertPolicyRule(r) {
    return {
        apiGroups: r.apiGroups ?? [],
        resources: r.resources ?? [],
        verbs: r.verbs ?? [],
        resourceNames: r.resourceNames,
    };
}
function convertSubject(s) {
    return {
        kind: s.kind,
        name: s.name,
        namespace: s.namespace,
    };
}
function convertRoleRef(r) {
    return {
        kind: r.kind,
        name: r.name,
        apiGroup: r.apiGroup,
    };
}
function convertRole(r) {
    const isCluster = !('metadata' in r && r.metadata?.namespace);
    return {
        kind: isCluster ? 'ClusterRole' : 'Role',
        apiVersion: 'rbac.authorization.k8s.io/v1',
        metadata: {
            name: r.metadata?.name ?? '',
            namespace: r.metadata?.namespace,
            annotations: r.metadata?.annotations,
            labels: r.metadata?.labels,
        },
        rules: (r.rules ?? []).map(convertPolicyRule),
        sourceFile: exports.CLUSTER_SOURCE,
        sourceLine: 0,
    };
}
function convertClusterRole(r) {
    return {
        kind: 'ClusterRole',
        apiVersion: 'rbac.authorization.k8s.io/v1',
        metadata: {
            name: r.metadata?.name ?? '',
            namespace: undefined,
            annotations: r.metadata?.annotations,
            labels: r.metadata?.labels,
        },
        rules: (r.rules ?? []).map(convertPolicyRule),
        sourceFile: exports.CLUSTER_SOURCE,
        sourceLine: 0,
    };
}
function convertRoleBinding(b) {
    return {
        kind: 'RoleBinding',
        apiVersion: 'rbac.authorization.k8s.io/v1',
        metadata: {
            name: b.metadata?.name ?? '',
            namespace: b.metadata?.namespace,
            annotations: b.metadata?.annotations,
            labels: b.metadata?.labels,
        },
        subjects: (b.subjects ?? []).map(convertSubject),
        roleRef: convertRoleRef(b.roleRef),
        sourceFile: exports.CLUSTER_SOURCE,
        sourceLine: 0,
    };
}
function convertClusterRoleBinding(b) {
    return {
        kind: 'ClusterRoleBinding',
        apiVersion: 'rbac.authorization.k8s.io/v1',
        metadata: {
            name: b.metadata?.name ?? '',
            namespace: undefined,
            annotations: b.metadata?.annotations,
            labels: b.metadata?.labels,
        },
        subjects: (b.subjects ?? []).map(convertSubject),
        roleRef: convertRoleRef(b.roleRef),
        sourceFile: exports.CLUSTER_SOURCE,
        sourceLine: 0,
    };
}
function convertServiceAccount(sa) {
    return {
        kind: 'ServiceAccount',
        apiVersion: 'v1',
        metadata: {
            name: sa.metadata?.name ?? '',
            namespace: sa.metadata?.namespace,
            annotations: sa.metadata?.annotations,
            labels: sa.metadata?.labels,
        },
        automountServiceAccountToken: sa.automountServiceAccountToken,
        sourceFile: exports.CLUSTER_SOURCE,
        sourceLine: 0,
    };
}
//# sourceMappingURL=converter.js.map