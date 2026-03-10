"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.fetchClusterResources = fetchClusterResources;
const client_node_1 = require("@kubernetes/client-node");
const converter_1 = require("./converter");
async function fetchClusterResources(opts) {
    const kc = new client_node_1.KubeConfig();
    kc.loadFromDefault();
    if (opts.context) {
        kc.setCurrentContext(opts.context);
    }
    const rbacApi = kc.makeApiClient(client_node_1.RbacAuthorizationV1Api);
    const coreApi = kc.makeApiClient(client_node_1.CoreV1Api);
    const resources = [];
    // Cluster-scoped resources (always fetched regardless of namespace)
    const [clusterRolesRes, clusterRoleBindingsRes] = await Promise.all([
        rbacApi.listClusterRole(),
        rbacApi.listClusterRoleBinding(),
    ]);
    for (const item of clusterRolesRes.items) {
        resources.push((0, converter_1.convertClusterRole)(item));
    }
    for (const item of clusterRoleBindingsRes.items) {
        resources.push((0, converter_1.convertClusterRoleBinding)(item));
    }
    // Namespace-scoped resources
    if (opts.allNamespaces || !opts.namespace) {
        const [rolesRes, roleBindingsRes, sasRes] = await Promise.all([
            rbacApi.listRoleForAllNamespaces(),
            rbacApi.listRoleBindingForAllNamespaces(),
            coreApi.listServiceAccountForAllNamespaces(),
        ]);
        for (const item of rolesRes.items)
            resources.push((0, converter_1.convertRole)(item));
        for (const item of roleBindingsRes.items)
            resources.push((0, converter_1.convertRoleBinding)(item));
        for (const item of sasRes.items)
            resources.push((0, converter_1.convertServiceAccount)(item));
    }
    else {
        const ns = opts.namespace;
        const [rolesRes, roleBindingsRes, sasRes] = await Promise.all([
            rbacApi.listNamespacedRole({ namespace: ns }),
            rbacApi.listNamespacedRoleBinding({ namespace: ns }),
            coreApi.listNamespacedServiceAccount({ namespace: ns }),
        ]);
        for (const item of rolesRes.items)
            resources.push((0, converter_1.convertRole)(item));
        for (const item of roleBindingsRes.items)
            resources.push((0, converter_1.convertRoleBinding)(item));
        for (const item of sasRes.items)
            resources.push((0, converter_1.convertServiceAccount)(item));
    }
    return resources;
}
//# sourceMappingURL=fetcher.js.map