"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.RB2_RULES = exports.RB2010 = exports.RB2009 = exports.RB2008 = exports.RB2007 = exports.RB2006 = exports.RB2005 = exports.RB2004 = exports.RB2003 = exports.RB2002 = exports.RB2001 = void 0;
exports.findEscalationChain = findEscalationChain;
const utils_1 = require("../utils");
function allRoles(ctx) {
    return [...ctx.graph.roles.values(), ...ctx.graph.clusterRoles.values()];
}
exports.RB2001 = {
    id: 'RB2001',
    severity: 'error',
    description: 'ClusterRoleBinding binds to `cluster-admin`',
    check(ctx) {
        const violations = [];
        const trusted = new Set(ctx.config.trustedClusterAdminBindings);
        for (const b of ctx.graph.clusterRoleBindings) {
            if (trusted.has(b.metadata.name))
                continue;
            if (b.roleRef.name === 'cluster-admin') {
                violations.push({
                    rule: 'RB2001',
                    severity: 'error',
                    message: `${(0, utils_1.bindingLabel)(b)} binds to 'cluster-admin' — grants full cluster access`,
                    resource: (0, utils_1.bindingLabel)(b),
                    file: b.sourceFile,
                    line: b.sourceLine,
                });
            }
        }
        return violations;
    },
};
exports.RB2002 = {
    id: 'RB2002',
    severity: 'error',
    description: 'Role with `escalate` verb',
    check(ctx) {
        const violations = [];
        for (const role of allRoles(ctx)) {
            for (const rule of role.rules) {
                if ((0, utils_1.hasVerb)(rule, 'escalate')) {
                    violations.push({
                        rule: 'RB2002',
                        severity: 'error',
                        message: `${(0, utils_1.resourceLabel)(role)} grants 'escalate' verb — allows privilege escalation`,
                        resource: (0, utils_1.resourceLabel)(role),
                        file: role.sourceFile,
                        line: role.sourceLine,
                    });
                    break;
                }
            }
        }
        return violations;
    },
};
exports.RB2003 = {
    id: 'RB2003',
    severity: 'error',
    description: 'Role with `bind` verb',
    check(ctx) {
        const violations = [];
        for (const role of allRoles(ctx)) {
            for (const rule of role.rules) {
                if ((0, utils_1.hasVerb)(rule, 'bind')) {
                    violations.push({
                        rule: 'RB2003',
                        severity: 'error',
                        message: `${(0, utils_1.resourceLabel)(role)} grants 'bind' verb — allows binding to higher-privileged roles`,
                        resource: (0, utils_1.resourceLabel)(role),
                        file: role.sourceFile,
                        line: role.sourceLine,
                    });
                    break;
                }
            }
        }
        return violations;
    },
};
exports.RB2004 = {
    id: 'RB2004',
    severity: 'error',
    description: 'Role can modify Role/ClusterRole (RBAC management)',
    check(ctx) {
        const violations = [];
        const rbacResources = ['roles', 'clusterroles'];
        const writeVerbs = ['create', 'update', 'patch', 'delete'];
        for (const role of allRoles(ctx)) {
            for (const rule of role.rules) {
                const targetsRbac = rbacResources.some(r => (0, utils_1.hasResource)(rule, r));
                const hasWrite = writeVerbs.some(v => (0, utils_1.hasVerb)(rule, v));
                if (targetsRbac && hasWrite) {
                    violations.push({
                        rule: 'RB2004',
                        severity: 'error',
                        message: `${(0, utils_1.resourceLabel)(role)} can modify Role/ClusterRole — allows RBAC manipulation`,
                        resource: (0, utils_1.resourceLabel)(role),
                        file: role.sourceFile,
                        line: role.sourceLine,
                    });
                    break;
                }
            }
        }
        return violations;
    },
};
exports.RB2005 = {
    id: 'RB2005',
    severity: 'error',
    description: 'Role can modify RoleBinding/ClusterRoleBinding',
    check(ctx) {
        const violations = [];
        const bindingResources = ['rolebindings', 'clusterrolebindings'];
        const writeVerbs = ['create', 'update', 'patch', 'delete'];
        for (const role of allRoles(ctx)) {
            for (const rule of role.rules) {
                const targetsBinding = bindingResources.some(r => (0, utils_1.hasResource)(rule, r));
                const hasWrite = writeVerbs.some(v => (0, utils_1.hasVerb)(rule, v));
                if (targetsBinding && hasWrite) {
                    violations.push({
                        rule: 'RB2005',
                        severity: 'error',
                        message: `${(0, utils_1.resourceLabel)(role)} can modify RoleBinding/ClusterRoleBinding — allows granting arbitrary permissions`,
                        resource: (0, utils_1.resourceLabel)(role),
                        file: role.sourceFile,
                        line: role.sourceLine,
                    });
                    break;
                }
            }
        }
        return violations;
    },
};
exports.RB2006 = {
    id: 'RB2006',
    severity: 'error',
    description: 'Impersonation permissions (users, groups, serviceaccounts)',
    check(ctx) {
        const violations = [];
        const impersonateResources = ['users', 'groups', 'serviceaccounts'];
        for (const role of allRoles(ctx)) {
            for (const rule of role.rules) {
                const targetsImpersonate = impersonateResources.some(r => (0, utils_1.hasResource)(rule, r));
                if (targetsImpersonate && (0, utils_1.hasVerb)(rule, 'impersonate')) {
                    violations.push({
                        rule: 'RB2006',
                        severity: 'error',
                        message: `${(0, utils_1.resourceLabel)(role)} grants impersonation of users/groups/serviceaccounts`,
                        resource: (0, utils_1.resourceLabel)(role),
                        file: role.sourceFile,
                        line: role.sourceLine,
                    });
                    break;
                }
            }
        }
        return violations;
    },
};
exports.RB2007 = {
    id: 'RB2007',
    severity: 'error',
    description: 'Role grants access to `tokenreviews` or `subjectaccessreviews`',
    check(ctx) {
        const violations = [];
        const authResources = ['tokenreviews', 'subjectaccessreviews'];
        for (const role of allRoles(ctx)) {
            for (const rule of role.rules) {
                if (authResources.some(r => (0, utils_1.hasResource)(rule, r))) {
                    violations.push({
                        rule: 'RB2007',
                        severity: 'error',
                        message: `${(0, utils_1.resourceLabel)(role)} grants access to tokenreviews/subjectaccessreviews — can verify or bypass auth`,
                        resource: (0, utils_1.resourceLabel)(role),
                        file: role.sourceFile,
                        line: role.sourceLine,
                    });
                    break;
                }
            }
        }
        return violations;
    },
};
exports.RB2008 = {
    id: 'RB2008',
    severity: 'warning',
    description: 'Role can create/update `ValidatingWebhookConfiguration`',
    check(ctx) {
        const violations = [];
        const writeVerbs = ['create', 'update', 'patch'];
        for (const role of allRoles(ctx)) {
            for (const rule of role.rules) {
                const targetsWebhook = (0, utils_1.hasResource)(rule, 'validatingwebhookconfigurations');
                const hasWrite = writeVerbs.some(v => (0, utils_1.hasVerb)(rule, v));
                if (targetsWebhook && hasWrite) {
                    violations.push({
                        rule: 'RB2008',
                        severity: 'warning',
                        message: `${(0, utils_1.resourceLabel)(role)} can create/update ValidatingWebhookConfiguration — can intercept API requests`,
                        resource: (0, utils_1.resourceLabel)(role),
                        file: role.sourceFile,
                        line: role.sourceLine,
                    });
                    break;
                }
            }
        }
        return violations;
    },
};
exports.RB2009 = {
    id: 'RB2009',
    severity: 'warning',
    description: 'Role can create/update `MutatingWebhookConfiguration`',
    check(ctx) {
        const violations = [];
        const writeVerbs = ['create', 'update', 'patch'];
        for (const role of allRoles(ctx)) {
            for (const rule of role.rules) {
                const targetsWebhook = (0, utils_1.hasResource)(rule, 'mutatingwebhookconfigurations');
                const hasWrite = writeVerbs.some(v => (0, utils_1.hasVerb)(rule, v));
                if (targetsWebhook && hasWrite) {
                    violations.push({
                        rule: 'RB2009',
                        severity: 'warning',
                        message: `${(0, utils_1.resourceLabel)(role)} can create/update MutatingWebhookConfiguration — can modify API requests`,
                        resource: (0, utils_1.resourceLabel)(role),
                        file: role.sourceFile,
                        line: role.sourceLine,
                    });
                    break;
                }
            }
        }
        return violations;
    },
};
function resolveRoleForBinding(binding, graph) {
    if (binding.roleRef.kind === 'ClusterRole') {
        return graph.clusterRoles.get(binding.roleRef.name);
    }
    const ns = binding.metadata.namespace;
    const key = (0, utils_1.makeRoleKey)(binding.roleRef.name, ns);
    return graph.roles.get(key);
}
function findEscalationChain(saName, saNamespace, graph, trusted) {
    const saKey = `${saNamespace}/${saName}`;
    const allBindings = [...graph.roleBindings, ...graph.clusterRoleBindings];
    // Find all bindings that include this SA
    const boundBindings = allBindings.filter(b => b.subjects.some(s => s.kind === 'ServiceAccount' && s.name === saName &&
        (s.namespace === saNamespace || b.kind === 'ClusterRoleBinding')));
    for (const binding of boundBindings) {
        if (trusted.has(binding.metadata.name) && binding.roleRef.name === 'cluster-admin') {
            continue;
        }
        if (binding.roleRef.name === 'cluster-admin') {
            return [saKey, `${binding.roleRef.kind}/${binding.roleRef.name}`];
        }
        const role = resolveRoleForBinding(binding, graph);
        if (role && (0, utils_1.isClusterAdminEquivalent)(role)) {
            return [saKey, `${binding.kind}/${binding.metadata.name}`, `${role.kind}/${role.metadata.name}`];
        }
    }
    return null;
}
exports.RB2010 = {
    id: 'RB2010',
    severity: 'error',
    description: 'Detected privilege escalation chain (A → B → cluster-admin)',
    check(ctx) {
        const violations = [];
        const trusted = new Set(ctx.config.trustedClusterAdminBindings);
        for (const sa of ctx.graph.serviceAccounts.values()) {
            const ns = sa.metadata.namespace || 'default';
            const chain = findEscalationChain(sa.metadata.name, ns, ctx.graph, trusted);
            if (chain) {
                violations.push({
                    rule: 'RB2010',
                    severity: 'error',
                    message: `ServiceAccount/${ns}/${sa.metadata.name} has privilege escalation path: ${chain.join(' → ')}`,
                    resource: `ServiceAccount/${ns}/${sa.metadata.name}`,
                    file: sa.sourceFile,
                    line: sa.sourceLine,
                });
            }
        }
        return violations;
    },
};
exports.RB2_RULES = [
    exports.RB2001, exports.RB2002, exports.RB2003, exports.RB2004, exports.RB2005,
    exports.RB2006, exports.RB2007, exports.RB2008, exports.RB2009, exports.RB2010,
];
//# sourceMappingURL=privilege-escalation.js.map