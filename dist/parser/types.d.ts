export type K8sKind = 'Role' | 'ClusterRole' | 'RoleBinding' | 'ClusterRoleBinding' | 'ServiceAccount';
export interface K8sObjectMeta {
    name: string;
    namespace?: string;
    annotations?: Record<string, string>;
    labels?: Record<string, string>;
}
export interface PolicyRule {
    apiGroups: string[];
    resources: string[];
    verbs: string[];
    resourceNames?: string[];
}
export interface Role {
    kind: 'Role' | 'ClusterRole';
    apiVersion: string;
    metadata: K8sObjectMeta;
    rules: PolicyRule[];
    sourceFile: string;
    sourceLine: number;
}
export interface Subject {
    kind: 'ServiceAccount' | 'User' | 'Group';
    name: string;
    namespace?: string;
}
export interface RoleRef {
    kind: 'Role' | 'ClusterRole';
    name: string;
    apiGroup: string;
}
export interface RoleBinding {
    kind: 'RoleBinding' | 'ClusterRoleBinding';
    apiVersion: string;
    metadata: K8sObjectMeta;
    subjects: Subject[];
    roleRef: RoleRef;
    sourceFile: string;
    sourceLine: number;
}
export interface ServiceAccount {
    kind: 'ServiceAccount';
    apiVersion: string;
    metadata: K8sObjectMeta;
    automountServiceAccountToken?: boolean;
    sourceFile: string;
    sourceLine: number;
}
export type K8sResource = Role | RoleBinding | ServiceAccount;
export interface ParseError {
    file: string;
    line: number;
    message: string;
}
export interface ParseResult {
    resources: K8sResource[];
    errors: ParseError[];
}
