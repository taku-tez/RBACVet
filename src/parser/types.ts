export type K8sKind =
  | 'Role'
  | 'ClusterRole'
  | 'RoleBinding'
  | 'ClusterRoleBinding'
  | 'ServiceAccount';

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

export type K8sResource = Role | RoleBinding | ServiceAccount | AuthorizationPolicy;

// Istio AuthorizationPolicy (security.istio.io/v1beta1)
export interface IstioSource {
  principals?: string[];
  namespaces?: string[];
  ipBlocks?: string[];
}

export interface IstioOperation {
  methods?: string[];
  paths?: string[];
  hosts?: string[];
  ports?: string[];
}

export interface IstioRule {
  from?: Array<{ source: IstioSource }>;
  to?: Array<{ operation: IstioOperation }>;
}

export interface AuthorizationPolicy {
  kind: 'AuthorizationPolicy';
  apiVersion: string;
  metadata: K8sObjectMeta;
  spec: {
    action?: 'ALLOW' | 'DENY' | 'AUDIT' | 'CUSTOM';
    rules?: IstioRule[];
    selector?: { matchLabels?: Record<string, string> };
  };
  sourceFile: string;
  sourceLine: number;
}

export interface ParseError {
  file: string;
  line: number;
  message: string;
}

export interface ParseResult {
  resources: K8sResource[];
  errors: ParseError[];
}
