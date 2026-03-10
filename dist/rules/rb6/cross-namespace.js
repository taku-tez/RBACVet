"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.RB6_RULES = exports.RB6001 = void 0;
const utils_1 = require("../utils");
exports.RB6001 = {
    id: 'RB6001',
    severity: 'warning',
    description: 'RoleBinding subjects a ServiceAccount from a different namespace',
    check(ctx) {
        const violations = [];
        for (const b of ctx.graph.roleBindings) {
            const bindingNs = b.metadata.namespace;
            for (const subject of b.subjects) {
                if (subject.kind === 'ServiceAccount' && subject.namespace && bindingNs) {
                    if (subject.namespace !== bindingNs) {
                        violations.push({
                            rule: 'RB6001',
                            severity: 'warning',
                            message: `${(0, utils_1.bindingLabel)(b)} in namespace '${bindingNs}' subjects ServiceAccount '${subject.name}' from namespace '${subject.namespace}'`,
                            resource: (0, utils_1.bindingLabel)(b),
                            file: b.sourceFile,
                            line: b.sourceLine,
                        });
                        break;
                    }
                }
            }
        }
        return violations;
    },
};
exports.RB6_RULES = [exports.RB6001];
//# sourceMappingURL=cross-namespace.js.map