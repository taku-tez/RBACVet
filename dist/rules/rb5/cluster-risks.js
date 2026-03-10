"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.RB5_RULES = exports.RB5006 = exports.RB5005 = exports.RB5004 = exports.RB5003 = exports.RB5002 = exports.RB5001 = void 0;
const utils_1 = require("../utils");
exports.RB5001 = {
    id: 'RB5001',
    severity: 'error',
    description: 'RoleBinding to `system:unauthenticated`',
    check(ctx) {
        const violations = [];
        const allBindings = [...ctx.graph.roleBindings, ...ctx.graph.clusterRoleBindings];
        for (const b of allBindings) {
            const hasUnauth = b.subjects.some(s => s.kind === 'Group' && s.name === 'system:unauthenticated');
            if (hasUnauth) {
                violations.push({
                    rule: 'RB5001',
                    severity: 'error',
                    message: `${(0, utils_1.bindingLabel)(b)} binds to 'system:unauthenticated' — grants access to anonymous users`,
                    resource: (0, utils_1.bindingLabel)(b),
                    file: b.sourceFile,
                    line: b.sourceLine,
                });
            }
        }
        return violations;
    },
};
exports.RB5002 = {
    id: 'RB5002',
    severity: 'error',
    description: 'RoleBinding to `system:anonymous`',
    check(ctx) {
        const violations = [];
        const allBindings = [...ctx.graph.roleBindings, ...ctx.graph.clusterRoleBindings];
        for (const b of allBindings) {
            const hasAnon = b.subjects.some(s => s.name === 'system:anonymous');
            if (hasAnon) {
                violations.push({
                    rule: 'RB5002',
                    severity: 'error',
                    message: `${(0, utils_1.bindingLabel)(b)} binds to 'system:anonymous' — grants access to unauthenticated users`,
                    resource: (0, utils_1.bindingLabel)(b),
                    file: b.sourceFile,
                    line: b.sourceLine,
                });
            }
        }
        return violations;
    },
};
exports.RB5003 = {
    id: 'RB5003',
    severity: 'warning',
    description: 'ClusterRoleBinding count exceeds threshold',
    check(ctx) {
        const violations = [];
        const threshold = 10;
        const count = ctx.graph.clusterRoleBindings.length;
        if (count > threshold) {
            violations.push({
                rule: 'RB5003',
                severity: 'warning',
                message: `Found ${count} ClusterRoleBindings (threshold: ${threshold}) — review cluster-wide permission grants`,
                resource: 'ClusterRoleBinding/*',
                file: ctx.graph.clusterRoleBindings[0]?.sourceFile || '',
                line: 1,
            });
        }
        return violations;
    },
};
exports.RB5004 = {
    id: 'RB5004',
    severity: 'warning',
    description: 'Multiple ClusterRoles with overlapping permissions',
    check(ctx) {
        const violations = [];
        const clusterRoles = [...ctx.graph.clusterRoles.values()];
        // Build resource-verb fingerprint per role
        const fingerprints = new Map();
        for (const role of clusterRoles) {
            const fp = role.rules
                .flatMap(r => r.resources.flatMap(res => r.verbs.map(v => `${res}:${v}`)))
                .sort();
            fingerprints.set(role.metadata.name, fp);
        }
        // Check pairs for significant overlap (>50% of permissions shared)
        const reported = new Set();
        for (let i = 0; i < clusterRoles.length; i++) {
            for (let j = i + 1; j < clusterRoles.length; j++) {
                const a = clusterRoles[i];
                const b = clusterRoles[j];
                const fpA = new Set(fingerprints.get(a.metadata.name) || []);
                const fpB = new Set(fingerprints.get(b.metadata.name) || []);
                if (fpA.size === 0 || fpB.size === 0)
                    continue;
                const intersection = [...fpA].filter(x => fpB.has(x));
                const overlapRatio = intersection.length / Math.min(fpA.size, fpB.size);
                const key = [a.metadata.name, b.metadata.name].sort().join('|');
                if (overlapRatio >= 0.5 && !reported.has(key)) {
                    reported.add(key);
                    violations.push({
                        rule: 'RB5004',
                        severity: 'warning',
                        message: `ClusterRole/${a.metadata.name} and ClusterRole/${b.metadata.name} have ${Math.round(overlapRatio * 100)}% overlapping permissions — consider consolidating`,
                        resource: `ClusterRole/${a.metadata.name}`,
                        file: a.sourceFile,
                        line: a.sourceLine,
                    });
                }
            }
        }
        return violations;
    },
};
exports.RB5005 = {
    id: 'RB5005',
    severity: 'info',
    description: 'Unused Role (no RoleBinding references it)',
    check(ctx) {
        const violations = [];
        const allBindings = [...ctx.graph.roleBindings, ...ctx.graph.clusterRoleBindings];
        const referencedRoles = new Set();
        for (const b of allBindings) {
            const ns = b.metadata.namespace;
            if (b.roleRef.kind === 'Role') {
                referencedRoles.add((0, utils_1.makeRoleKey)(b.roleRef.name, ns));
            }
            else {
                referencedRoles.add(b.roleRef.name);
            }
        }
        // Check namespaced Roles
        for (const [key, role] of ctx.graph.roles) {
            if (!referencedRoles.has(key)) {
                violations.push({
                    rule: 'RB5005',
                    severity: 'info',
                    message: `${(0, utils_1.resourceLabel)(role)} is not referenced by any RoleBinding`,
                    resource: (0, utils_1.resourceLabel)(role),
                    file: role.sourceFile,
                    line: role.sourceLine,
                });
            }
        }
        // Check ClusterRoles (skip system: roles)
        for (const [name, role] of ctx.graph.clusterRoles) {
            if (name.startsWith('system:'))
                continue;
            if (!referencedRoles.has(name)) {
                violations.push({
                    rule: 'RB5005',
                    severity: 'info',
                    message: `${(0, utils_1.resourceLabel)(role)} is not referenced by any RoleBinding or ClusterRoleBinding`,
                    resource: (0, utils_1.resourceLabel)(role),
                    file: role.sourceFile,
                    line: role.sourceLine,
                });
            }
        }
        return violations;
    },
};
exports.RB5006 = {
    id: 'RB5006',
    severity: 'info',
    description: 'Orphaned RoleBinding (references non-existent Role)',
    check(ctx) {
        const violations = [];
        for (const b of ctx.graph.roleBindings) {
            const ns = b.metadata.namespace;
            let exists;
            if (b.roleRef.kind === 'ClusterRole') {
                exists = ctx.graph.clusterRoles.has(b.roleRef.name);
            }
            else {
                exists = ctx.graph.roles.has((0, utils_1.makeRoleKey)(b.roleRef.name, ns));
            }
            if (!exists) {
                violations.push({
                    rule: 'RB5006',
                    severity: 'info',
                    message: `${(0, utils_1.bindingLabel)(b)} references ${b.roleRef.kind}/${b.roleRef.name} which was not found in scanned manifests`,
                    resource: (0, utils_1.bindingLabel)(b),
                    file: b.sourceFile,
                    line: b.sourceLine,
                });
            }
        }
        for (const b of ctx.graph.clusterRoleBindings) {
            const exists = ctx.graph.clusterRoles.has(b.roleRef.name) ||
                b.roleRef.name === 'cluster-admin';
            if (!exists) {
                violations.push({
                    rule: 'RB5006',
                    severity: 'info',
                    message: `${(0, utils_1.bindingLabel)(b)} references ClusterRole/${b.roleRef.name} which was not found in scanned manifests`,
                    resource: (0, utils_1.bindingLabel)(b),
                    file: b.sourceFile,
                    line: b.sourceLine,
                });
            }
        }
        return violations;
    },
};
exports.RB5_RULES = [
    exports.RB5001, exports.RB5002, exports.RB5003, exports.RB5004, exports.RB5005, exports.RB5006,
];
//# sourceMappingURL=cluster-risks.js.map