"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.RB3_RULES = exports.RB3008 = exports.RB3007 = exports.RB3006 = exports.RB3005 = exports.RB3004 = exports.RB3003 = exports.RB3002 = exports.RB3001 = void 0;
const utils_1 = require("../utils");
function allRoles(ctx) {
    return [...ctx.graph.roles.values(), ...ctx.graph.clusterRoles.values()];
}
exports.RB3001 = {
    id: 'RB3001',
    severity: 'warning',
    description: 'Role grants read access to `secrets`',
    check(ctx) {
        const violations = [];
        const readVerbs = ['get', 'list', 'watch'];
        for (const role of allRoles(ctx)) {
            for (const rule of role.rules) {
                if ((0, utils_1.hasResource)(rule, 'secrets') && readVerbs.some(v => (0, utils_1.hasVerb)(rule, v))) {
                    violations.push({
                        rule: 'RB3001',
                        severity: 'warning',
                        message: `${(0, utils_1.resourceLabel)(role)} grants read access to 'secrets'`,
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
exports.RB3002 = {
    id: 'RB3002',
    severity: 'error',
    description: 'Role grants write access to `secrets`',
    check(ctx) {
        const violations = [];
        const writeVerbs = ['create', 'update', 'patch', 'delete'];
        for (const role of allRoles(ctx)) {
            for (const rule of role.rules) {
                if ((0, utils_1.hasResource)(rule, 'secrets') && writeVerbs.some(v => (0, utils_1.hasVerb)(rule, v))) {
                    violations.push({
                        rule: 'RB3002',
                        severity: 'error',
                        message: `${(0, utils_1.resourceLabel)(role)} grants write access to 'secrets' — can exfiltrate or tamper with credentials`,
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
exports.RB3003 = {
    id: 'RB3003',
    severity: 'warning',
    description: 'Role grants access to `configmaps` with write',
    check(ctx) {
        const violations = [];
        const writeVerbs = ['create', 'update', 'patch', 'delete'];
        for (const role of allRoles(ctx)) {
            for (const rule of role.rules) {
                if ((0, utils_1.hasResource)(rule, 'configmaps') && writeVerbs.some(v => (0, utils_1.hasVerb)(rule, v))) {
                    violations.push({
                        rule: 'RB3003',
                        severity: 'warning',
                        message: `${(0, utils_1.resourceLabel)(role)} grants write access to 'configmaps' — can inject configuration`,
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
exports.RB3004 = {
    id: 'RB3004',
    severity: 'error',
    description: 'Role can `exec` into pods (`pods/exec`)',
    check(ctx) {
        const violations = [];
        for (const role of allRoles(ctx)) {
            for (const rule of role.rules) {
                if ((0, utils_1.hasResource)(rule, 'pods/exec')) {
                    violations.push({
                        rule: 'RB3004',
                        severity: 'error',
                        message: `${(0, utils_1.resourceLabel)(role)} can exec into pods — allows arbitrary command execution`,
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
exports.RB3005 = {
    id: 'RB3005',
    severity: 'warning',
    description: 'Role can `attach` to pods (`pods/attach`)',
    check(ctx) {
        const violations = [];
        for (const role of allRoles(ctx)) {
            for (const rule of role.rules) {
                if ((0, utils_1.hasResource)(rule, 'pods/attach')) {
                    violations.push({
                        rule: 'RB3005',
                        severity: 'warning',
                        message: `${(0, utils_1.resourceLabel)(role)} can attach to pods — allows interacting with running containers`,
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
exports.RB3006 = {
    id: 'RB3006',
    severity: 'warning',
    description: 'Role can access pod logs (`pods/log`)',
    check(ctx) {
        const violations = [];
        for (const role of allRoles(ctx)) {
            for (const rule of role.rules) {
                if ((0, utils_1.hasResource)(rule, 'pods/log')) {
                    violations.push({
                        rule: 'RB3006',
                        severity: 'warning',
                        message: `${(0, utils_1.resourceLabel)(role)} can access pod logs — may expose sensitive runtime data`,
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
exports.RB3007 = {
    id: 'RB3007',
    severity: 'error',
    description: 'Role can access `etcd` directly',
    check(ctx) {
        const violations = [];
        for (const role of allRoles(ctx)) {
            for (const rule of role.rules) {
                if ((0, utils_1.hasResource)(rule, 'etcd') || (0, utils_1.hasResource)(rule, 'etcdclusters')) {
                    violations.push({
                        rule: 'RB3007',
                        severity: 'error',
                        message: `${(0, utils_1.resourceLabel)(role)} can access etcd — grants access to all cluster data`,
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
exports.RB3008 = {
    id: 'RB3008',
    severity: 'warning',
    description: 'Role grants access to `persistentvolumes`',
    check(ctx) {
        const violations = [];
        for (const role of allRoles(ctx)) {
            for (const rule of role.rules) {
                if ((0, utils_1.hasResource)(rule, 'persistentvolumes') && (0, utils_1.hasAnyVerb)(rule, ['get', 'list', 'create', 'update', 'patch', 'delete'])) {
                    violations.push({
                        rule: 'RB3008',
                        severity: 'warning',
                        message: `${(0, utils_1.resourceLabel)(role)} grants access to 'persistentvolumes' — can access persistent storage`,
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
exports.RB3_RULES = [
    exports.RB3001, exports.RB3002, exports.RB3003, exports.RB3004, exports.RB3005, exports.RB3006, exports.RB3007, exports.RB3008,
];
//# sourceMappingURL=secret-access.js.map