import { KubeConfig, RbacAuthorizationV1Api, CoreV1Api } from '@kubernetes/client-node';
import type { K8sResource } from '../parser/types';
import {
  convertRole, convertClusterRole,
  convertRoleBinding, convertClusterRoleBinding,
  convertServiceAccount,
} from './converter';

export interface ClusterFetchOptions {
  context?: string;
  namespace?: string;
  allNamespaces: boolean;
}

export async function fetchClusterResources(opts: ClusterFetchOptions): Promise<K8sResource[]> {
  const kc = new KubeConfig();
  kc.loadFromDefault();

  if (opts.context) {
    kc.setCurrentContext(opts.context);
  }

  const rbacApi = kc.makeApiClient(RbacAuthorizationV1Api);
  const coreApi = kc.makeApiClient(CoreV1Api);

  const resources: K8sResource[] = [];

  // Cluster-scoped resources (always fetched regardless of namespace)
  const [clusterRolesRes, clusterRoleBindingsRes] = await Promise.all([
    rbacApi.listClusterRole(),
    rbacApi.listClusterRoleBinding(),
  ]);

  for (const item of clusterRolesRes.items) {
    resources.push(convertClusterRole(item));
  }
  for (const item of clusterRoleBindingsRes.items) {
    resources.push(convertClusterRoleBinding(item));
  }

  // Namespace-scoped resources
  if (opts.allNamespaces || !opts.namespace) {
    const [rolesRes, roleBindingsRes, sasRes] = await Promise.all([
      rbacApi.listRoleForAllNamespaces(),
      rbacApi.listRoleBindingForAllNamespaces(),
      coreApi.listServiceAccountForAllNamespaces(),
    ]);
    for (const item of rolesRes.items) resources.push(convertRole(item));
    for (const item of roleBindingsRes.items) resources.push(convertRoleBinding(item));
    for (const item of sasRes.items) resources.push(convertServiceAccount(item));
  } else {
    const ns = opts.namespace;
    const [rolesRes, roleBindingsRes, sasRes] = await Promise.all([
      rbacApi.listNamespacedRole({ namespace: ns }),
      rbacApi.listNamespacedRoleBinding({ namespace: ns }),
      coreApi.listNamespacedServiceAccount({ namespace: ns }),
    ]);
    for (const item of rolesRes.items) resources.push(convertRole(item));
    for (const item of roleBindingsRes.items) resources.push(convertRoleBinding(item));
    for (const item of sasRes.items) resources.push(convertServiceAccount(item));
  }

  return resources;
}
