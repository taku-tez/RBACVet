"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.formatDiff = formatDiff;
const chalk_1 = __importDefault(require("chalk"));
function formatDiff(entries, useColor) {
    if (!useColor)
        chalk_1.default.level = 0;
    if (entries.length === 0) {
        return chalk_1.default.green('No differences found — cluster matches local manifests');
    }
    const lines = [];
    for (const entry of entries) {
        const ns = entry.namespace ? `${entry.namespace}/` : '';
        const label = `${entry.kind}/${ns}${entry.name}`;
        switch (entry.status) {
            case 'added':
                lines.push(chalk_1.default.green(`+ ${label}  [only in local manifests — not in cluster]`));
                break;
            case 'removed':
                lines.push(chalk_1.default.red(`- ${label}  [only in cluster — not in local manifests]`));
                break;
            case 'changed':
                lines.push(chalk_1.default.yellow(`~ ${label}  [changed]`));
                if (entry.changes) {
                    for (const ch of entry.changes) {
                        lines.push(chalk_1.default.dim(`    cluster: ${JSON.stringify(ch.clusterValue)}`));
                        lines.push(chalk_1.default.dim(`    local:   ${JSON.stringify(ch.localValue)}`));
                    }
                }
                break;
        }
    }
    lines.push('');
    const added = entries.filter(e => e.status === 'added').length;
    const removed = entries.filter(e => e.status === 'removed').length;
    const changed = entries.filter(e => e.status === 'changed').length;
    const parts = [];
    if (added > 0)
        parts.push(chalk_1.default.green(`${added} added`));
    if (removed > 0)
        parts.push(chalk_1.default.red(`${removed} removed`));
    if (changed > 0)
        parts.push(chalk_1.default.yellow(`${changed} changed`));
    lines.push(parts.join(', '));
    return lines.join('\n');
}
//# sourceMappingURL=diff.js.map