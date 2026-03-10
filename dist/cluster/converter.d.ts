import type { V1Role, V1ClusterRole, V1RoleBinding, V1ClusterRoleBinding, V1ServiceAccount } from '@kubernetes/client-node';
import type { Role, RoleBinding, ServiceAccount } from '../parser/types';
export declare const CLUSTER_SOURCE = "<cluster>";
export declare function convertRole(r: V1Role | V1ClusterRole): Role;
export declare function convertClusterRole(r: V1ClusterRole): Role;
export declare function convertRoleBinding(b: V1RoleBinding): RoleBinding;
export declare function convertClusterRoleBinding(b: V1ClusterRoleBinding): RoleBinding;
export declare function convertServiceAccount(sa: V1ServiceAccount): ServiceAccount;
