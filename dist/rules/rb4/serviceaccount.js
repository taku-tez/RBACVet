"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.RB4_RULES = exports.RB4008 = exports.RB4007 = exports.RB4006 = exports.RB4005 = exports.RB4004 = exports.RB4003 = exports.RB4002 = exports.RB4001 = void 0;
const utils_1 = require("../utils");
function saLabel(sa) {
    const ns = sa.metadata.namespace || 'default';
    return `ServiceAccount/${ns}/${sa.metadata.name}`;
}
exports.RB4001 = {
    id: 'RB4001',
    severity: 'warning',
    description: '`automountServiceAccountToken` not set to `false`',
    check(ctx) {
        const violations = [];
        for (const sa of ctx.graph.serviceAccounts.values()) {
            if (sa.automountServiceAccountToken !== false) {
                violations.push({
                    rule: 'RB4001',
                    severity: 'warning',
                    message: `${saLabel(sa)} does not set automountServiceAccountToken: false — token is auto-mounted`,
                    resource: saLabel(sa),
                    file: sa.sourceFile,
                    line: sa.sourceLine,
                });
            }
        }
        return violations;
    },
};
exports.RB4002 = {
    id: 'RB4002',
    severity: 'warning',
    description: 'ServiceAccount name is `default` used in RoleBinding',
    check(ctx) {
        const violations = [];
        const allBindings = [...ctx.graph.roleBindings, ...ctx.graph.clusterRoleBindings];
        for (const b of allBindings) {
            const hasDefaultSA = b.subjects.some(s => s.kind === 'ServiceAccount' && s.name === 'default');
            if (hasDefaultSA) {
                violations.push({
                    rule: 'RB4002',
                    severity: 'warning',
                    message: `${(0, utils_1.bindingLabel)(b)} binds to the 'default' ServiceAccount — use a dedicated ServiceAccount`,
                    resource: (0, utils_1.bindingLabel)(b),
                    file: b.sourceFile,
                    line: b.sourceLine,
                });
            }
        }
        return violations;
    },
};
exports.RB4003 = {
    id: 'RB4003',
    severity: 'error',
    description: 'ServiceAccount bound to ClusterRole with broad permissions',
    check(ctx) {
        const violations = [];
        for (const b of ctx.graph.clusterRoleBindings) {
            const hasSASubject = b.subjects.some(s => s.kind === 'ServiceAccount');
            if (!hasSASubject)
                continue;
            const role = ctx.graph.clusterRoles.get(b.roleRef.name);
            if (!role)
                continue;
            const isBroad = role.rules.some(rule => (0, utils_1.hasWildcard)(rule.verbs) || (0, utils_1.hasWildcard)(rule.resources));
            if (isBroad) {
                violations.push({
                    rule: 'RB4003',
                    severity: 'error',
                    message: `${(0, utils_1.bindingLabel)(b)} binds ServiceAccount to ClusterRole '${b.roleRef.name}' with broad permissions`,
                    resource: (0, utils_1.bindingLabel)(b),
                    file: b.sourceFile,
                    line: b.sourceLine,
                });
            }
        }
        return violations;
    },
};
exports.RB4004 = {
    id: 'RB4004',
    severity: 'warning',
    description: 'ServiceAccount without namespace scope',
    check(ctx) {
        const violations = [];
        for (const sa of ctx.graph.serviceAccounts.values()) {
            if (!sa.metadata.namespace) {
                violations.push({
                    rule: 'RB4004',
                    severity: 'warning',
                    message: `ServiceAccount/${sa.metadata.name} has no namespace defined — may be applied to unintended namespace`,
                    resource: `ServiceAccount/${sa.metadata.name}`,
                    file: sa.sourceFile,
                    line: sa.sourceLine,
                });
            }
        }
        return violations;
    },
};
exports.RB4005 = {
    id: 'RB4005',
    severity: 'info',
    description: 'ServiceAccount with no associated Role/ClusterRole',
    check(ctx) {
        const violations = [];
        const allBindings = [...ctx.graph.roleBindings, ...ctx.graph.clusterRoleBindings];
        for (const sa of ctx.graph.serviceAccounts.values()) {
            const ns = sa.metadata.namespace;
            const isReferenced = allBindings.some(b => b.subjects.some(s => s.kind === 'ServiceAccount' && s.name === sa.metadata.name &&
                (!ns || s.namespace === ns || b.kind === 'ClusterRoleBinding')));
            if (!isReferenced) {
                violations.push({
                    rule: 'RB4005',
                    severity: 'info',
                    message: `${saLabel(sa)} has no RoleBinding or ClusterRoleBinding referencing it`,
                    resource: saLabel(sa),
                    file: sa.sourceFile,
                    line: sa.sourceLine,
                });
            }
        }
        return violations;
    },
};
exports.RB4006 = {
    id: 'RB4006',
    severity: 'warning',
    description: 'RoleBinding in multiple namespaces for same SA',
    check(ctx) {
        const violations = [];
        // Track namespaces per SA
        const saNamespaces = new Map();
        const saBindingFiles = new Map();
        for (const b of ctx.graph.roleBindings) {
            for (const s of b.subjects) {
                if (s.kind === 'ServiceAccount') {
                    const key = `${s.namespace || 'default'}/${s.name}`;
                    const bindingNs = b.metadata.namespace || 'default';
                    if (!saNamespaces.has(key)) {
                        saNamespaces.set(key, new Set());
                        saBindingFiles.set(key, { file: b.sourceFile, line: b.sourceLine });
                    }
                    saNamespaces.get(key).add(bindingNs);
                }
            }
        }
        for (const [saKey, namespaces] of saNamespaces) {
            if (namespaces.size > 1) {
                const loc = saBindingFiles.get(saKey);
                violations.push({
                    rule: 'RB4006',
                    severity: 'warning',
                    message: `ServiceAccount '${saKey}' is bound via RoleBindings in ${namespaces.size} different namespaces: ${[...namespaces].join(', ')}`,
                    resource: `ServiceAccount/${saKey}`,
                    file: loc.file,
                    line: loc.line,
                });
            }
        }
        return violations;
    },
};
exports.RB4007 = {
    id: 'RB4007',
    severity: 'info',
    description: 'ServiceAccount without description annotation',
    check(ctx) {
        const violations = [];
        for (const sa of ctx.graph.serviceAccounts.values()) {
            const annotations = sa.metadata.annotations || {};
            const hasDesc = annotations['description'] || annotations['kubectl.kubernetes.io/description'];
            if (!hasDesc) {
                violations.push({
                    rule: 'RB4007',
                    severity: 'info',
                    message: `${saLabel(sa)} has no description annotation`,
                    resource: saLabel(sa),
                    file: sa.sourceFile,
                    line: sa.sourceLine,
                });
            }
        }
        return violations;
    },
};
exports.RB4008 = {
    id: 'RB4008',
    severity: 'warning',
    description: 'ServiceAccount token projected without expiry',
    check(ctx) {
        // This rule would normally inspect Pod specs for projected service account tokens
        // In manifest mode, we flag SAs that have automountServiceAccountToken: true explicitly
        // and no token expiry annotations as a proxy check
        const violations = [];
        for (const sa of ctx.graph.serviceAccounts.values()) {
            if (sa.automountServiceAccountToken === true) {
                const annotations = sa.metadata.annotations || {};
                const hasExpiryHint = annotations['token-expiry'] || annotations['rbacvet/token-expiry'];
                if (!hasExpiryHint) {
                    violations.push({
                        rule: 'RB4008',
                        severity: 'warning',
                        message: `${saLabel(sa)} explicitly enables token auto-mounting without expiry annotation`,
                        resource: saLabel(sa),
                        file: sa.sourceFile,
                        line: sa.sourceLine,
                    });
                }
            }
        }
        return violations;
    },
};
exports.RB4_RULES = [
    exports.RB4001, exports.RB4002, exports.RB4003, exports.RB4004, exports.RB4005, exports.RB4006, exports.RB4007, exports.RB4008,
];
//# sourceMappingURL=serviceaccount.js.map