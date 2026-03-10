"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.RB1_RULES = exports.RB1012 = exports.RB1011 = exports.RB1010 = exports.RB1009 = exports.RB1008 = exports.RB1007 = exports.RB1006 = exports.RB1005 = exports.RB1004 = exports.RB1003 = exports.RB1002 = exports.RB1001 = void 0;
const utils_1 = require("../utils");
function allRoles(ctx) {
    return [...ctx.graph.roles.values(), ...ctx.graph.clusterRoles.values()];
}
exports.RB1001 = {
    id: 'RB1001',
    severity: 'error',
    description: 'Wildcard `*` in verbs',
    check(ctx) {
        const violations = [];
        for (const role of allRoles(ctx)) {
            for (const rule of role.rules) {
                if ((0, utils_1.hasWildcard)(rule.verbs)) {
                    violations.push({
                        rule: 'RB1001',
                        severity: 'error',
                        message: `${(0, utils_1.resourceLabel)(role)} has wildcard verb '*' — grants all actions`,
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
exports.RB1002 = {
    id: 'RB1002',
    severity: 'error',
    description: 'Wildcard `*` in resources',
    check(ctx) {
        const violations = [];
        for (const role of allRoles(ctx)) {
            for (const rule of role.rules) {
                if ((0, utils_1.hasWildcard)(rule.resources)) {
                    violations.push({
                        rule: 'RB1002',
                        severity: 'error',
                        message: `${(0, utils_1.resourceLabel)(role)} has wildcard resource '*' — grants access to all resources`,
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
exports.RB1003 = {
    id: 'RB1003',
    severity: 'warning',
    description: 'Wildcard `*` in apiGroups',
    check(ctx) {
        const violations = [];
        for (const role of allRoles(ctx)) {
            for (const rule of role.rules) {
                if ((0, utils_1.hasWildcard)(rule.apiGroups)) {
                    violations.push({
                        rule: 'RB1003',
                        severity: 'warning',
                        message: `${(0, utils_1.resourceLabel)(role)} has wildcard apiGroup '*' — grants access across all API groups`,
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
exports.RB1004 = {
    id: 'RB1004',
    severity: 'error',
    description: '`create` + `delete` combined on same resource',
    check(ctx) {
        const violations = [];
        for (const role of allRoles(ctx)) {
            for (const rule of role.rules) {
                if ((0, utils_1.hasVerb)(rule, 'create') && (0, utils_1.hasVerb)(rule, 'delete')) {
                    violations.push({
                        rule: 'RB1004',
                        severity: 'error',
                        message: `${(0, utils_1.resourceLabel)(role)} combines 'create' and 'delete' on the same resource`,
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
exports.RB1005 = {
    id: 'RB1005',
    severity: 'warning',
    description: '`update` + `patch` combined with no resource restriction',
    check(ctx) {
        const violations = [];
        for (const role of allRoles(ctx)) {
            for (const rule of role.rules) {
                const hasUpdate = (0, utils_1.hasVerb)(rule, 'update');
                const hasPatch = (0, utils_1.hasVerb)(rule, 'patch');
                const noRestriction = (0, utils_1.hasWildcard)(rule.resources);
                if (hasUpdate && hasPatch && noRestriction) {
                    violations.push({
                        rule: 'RB1005',
                        severity: 'warning',
                        message: `${(0, utils_1.resourceLabel)(role)} combines 'update' and 'patch' on all resources`,
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
exports.RB1006 = {
    id: 'RB1006',
    severity: 'error',
    description: 'ClusterRole with write access to all core resources',
    check(ctx) {
        const violations = [];
        for (const role of ctx.graph.clusterRoles.values()) {
            for (const rule of role.rules) {
                const coreGroup = rule.apiGroups.includes('') || (0, utils_1.hasWildcard)(rule.apiGroups);
                const allResources = (0, utils_1.hasWildcard)(rule.resources);
                const hasWrite = (0, utils_1.hasAnyVerb)(rule, ['create', 'update', 'patch', 'delete']);
                if (coreGroup && allResources && hasWrite) {
                    violations.push({
                        rule: 'RB1006',
                        severity: 'error',
                        message: `${(0, utils_1.resourceLabel)(role)} (ClusterRole) grants write access to all core resources`,
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
exports.RB1007 = {
    id: 'RB1007',
    severity: 'warning',
    description: 'Role grants `list` on all resources',
    check(ctx) {
        const violations = [];
        for (const role of allRoles(ctx)) {
            for (const rule of role.rules) {
                if ((0, utils_1.hasVerb)(rule, 'list') && (0, utils_1.hasWildcard)(rule.resources)) {
                    violations.push({
                        rule: 'RB1007',
                        severity: 'warning',
                        message: `${(0, utils_1.resourceLabel)(role)} grants 'list' on all resources`,
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
exports.RB1008 = {
    id: 'RB1008',
    severity: 'warning',
    description: 'Role grants `watch` on all resources',
    check(ctx) {
        const violations = [];
        for (const role of allRoles(ctx)) {
            for (const rule of role.rules) {
                if ((0, utils_1.hasVerb)(rule, 'watch') && (0, utils_1.hasWildcard)(rule.resources)) {
                    violations.push({
                        rule: 'RB1008',
                        severity: 'warning',
                        message: `${(0, utils_1.resourceLabel)(role)} grants 'watch' on all resources`,
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
exports.RB1009 = {
    id: 'RB1009',
    severity: 'error',
    description: 'Role with `*` verbs on `nodes` resource',
    check(ctx) {
        const violations = [];
        for (const role of allRoles(ctx)) {
            for (const rule of role.rules) {
                if ((0, utils_1.hasWildcard)(rule.verbs) && (0, utils_1.hasResource)(rule, 'nodes')) {
                    violations.push({
                        rule: 'RB1009',
                        severity: 'error',
                        message: `${(0, utils_1.resourceLabel)(role)} grants all verbs on 'nodes' resource`,
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
exports.RB1010 = {
    id: 'RB1010',
    severity: 'error',
    description: 'Role with `*` verbs on `namespaces` resource',
    check(ctx) {
        const violations = [];
        for (const role of allRoles(ctx)) {
            for (const rule of role.rules) {
                if ((0, utils_1.hasWildcard)(rule.verbs) && (0, utils_1.hasResource)(rule, 'namespaces')) {
                    violations.push({
                        rule: 'RB1010',
                        severity: 'error',
                        message: `${(0, utils_1.resourceLabel)(role)} grants all verbs on 'namespaces' resource`,
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
exports.RB1011 = {
    id: 'RB1011',
    severity: 'warning',
    description: 'Role with `deletecollection` verb',
    check(ctx) {
        const violations = [];
        for (const role of allRoles(ctx)) {
            for (const rule of role.rules) {
                if ((0, utils_1.hasVerb)(rule, 'deletecollection')) {
                    violations.push({
                        rule: 'RB1011',
                        severity: 'warning',
                        message: `${(0, utils_1.resourceLabel)(role)} grants 'deletecollection' verb — allows bulk deletion`,
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
exports.RB1012 = {
    id: 'RB1012',
    severity: 'info',
    description: 'Role with more than 20 permission rules',
    check(ctx) {
        const violations = [];
        for (const role of allRoles(ctx)) {
            if (role.rules.length > 20) {
                violations.push({
                    rule: 'RB1012',
                    severity: 'info',
                    message: `${(0, utils_1.resourceLabel)(role)} has ${role.rules.length} permission rules — consider splitting into smaller roles`,
                    resource: (0, utils_1.resourceLabel)(role),
                    file: role.sourceFile,
                    line: role.sourceLine,
                });
            }
        }
        return violations;
    },
};
exports.RB1_RULES = [
    exports.RB1001, exports.RB1002, exports.RB1003, exports.RB1004, exports.RB1005, exports.RB1006,
    exports.RB1007, exports.RB1008, exports.RB1009, exports.RB1010, exports.RB1011, exports.RB1012,
];
//# sourceMappingURL=least-privilege.js.map