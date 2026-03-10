"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.formatJSON = formatJSON;
function formatJSON(violations, scores, filesScanned, resources) {
    const resourcesFound = {};
    for (const r of resources) {
        resourcesFound[r.kind] = (resourcesFound[r.kind] || 0) + 1;
    }
    const output = {
        violations,
        riskScores: scores,
        summary: {
            errors: violations.filter(v => v.severity === 'error').length,
            warnings: violations.filter(v => v.severity === 'warning').length,
            infos: violations.filter(v => v.severity === 'info').length,
            filesScanned,
            resourcesFound,
        },
    };
    return JSON.stringify(output, null, 2);
}
//# sourceMappingURL=json.js.map