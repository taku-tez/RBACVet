"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.formatSARIF = formatSARIF;
const index_1 = require("../rules/index");
const SEVERITY_MAP = {
    error: 'error',
    warning: 'warning',
    info: 'note',
};
function formatSARIF(violations) {
    const usedRules = new Set(violations.map(v => v.rule));
    const rules = Array.from(usedRules).map(id => {
        const rule = index_1.RULE_MAP.get(id);
        return {
            id,
            shortDescription: { text: rule?.description || id },
            defaultConfiguration: { level: SEVERITY_MAP[rule?.severity || 'info'] || 'note' },
        };
    });
    const sarif = {
        $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
        version: '2.1.0',
        runs: [{
                tool: {
                    driver: {
                        name: 'rbacvet',
                        version: '0.1.0',
                        informationUri: 'https://github.com/RBACVet/rbacvet',
                        rules,
                    },
                },
                results: violations.map(v => ({
                    ruleId: v.rule,
                    level: SEVERITY_MAP[v.severity] || 'note',
                    message: { text: v.message },
                    locations: [{
                            physicalLocation: {
                                artifactLocation: { uri: v.file },
                                region: { startLine: Math.max(v.line, 1), startColumn: 1 },
                            },
                        }],
                })),
            }],
    };
    return JSON.stringify(sarif, null, 2);
}
//# sourceMappingURL=sarif.js.map