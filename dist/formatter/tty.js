"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.formatTTY = formatTTY;
const chalk_1 = __importDefault(require("chalk"));
const SEVERITY_COLOR = {
    error: chalk_1.default.red,
    warning: chalk_1.default.yellow,
    info: chalk_1.default.cyan,
};
const LEVEL_COLOR = {
    CRITICAL: chalk_1.default.bgRed.white.bold,
    HIGH: chalk_1.default.red.bold,
    MEDIUM: chalk_1.default.yellow.bold,
    LOW: chalk_1.default.green,
};
function pad(s, len) {
    return s.padEnd(len);
}
function formatTTY(violations, scores, useColor) {
    if (!useColor) {
        chalk_1.default.level = 0;
    }
    const lines = [];
    // Group violations by file
    const byFile = new Map();
    for (const v of violations) {
        const existing = byFile.get(v.file) || [];
        existing.push(v);
        byFile.set(v.file, existing);
    }
    for (const [file, fileViolations] of byFile) {
        lines.push(chalk_1.default.underline(file));
        for (const v of fileViolations) {
            const colorFn = SEVERITY_COLOR[v.severity] || chalk_1.default.white;
            const severityStr = colorFn(pad(v.severity, 7));
            const ruleStr = chalk_1.default.bold(pad(v.rule, 8));
            const resource = chalk_1.default.dim(pad(v.resource, 40));
            lines.push(`  ${ruleStr}  ${severityStr}  ${resource}  ${v.message}`);
        }
        lines.push('');
    }
    // Risk scores
    if (scores.length > 0) {
        lines.push(chalk_1.default.bold('Risk Scores:'));
        for (const s of scores) {
            if (s.score === 0)
                continue;
            const levelFn = LEVEL_COLOR[s.level] || chalk_1.default.white;
            const scoreStr = `${s.score}/100`;
            lines.push(`  ${s.name.padEnd(50)} ${scoreStr.padStart(7)}  ${levelFn(s.level)}`);
            if (s.escalationPath) {
                lines.push(`    Escalation path: ${s.escalationPath.join(' → ')}`);
            }
        }
        lines.push('');
    }
    // Summary
    const errors = violations.filter(v => v.severity === 'error').length;
    const warnings = violations.filter(v => v.severity === 'warning').length;
    const infos = violations.filter(v => v.severity === 'info').length;
    const parts = [];
    if (errors > 0)
        parts.push(chalk_1.default.red(`${errors} error${errors !== 1 ? 's' : ''}`));
    if (warnings > 0)
        parts.push(chalk_1.default.yellow(`${warnings} warning${warnings !== 1 ? 's' : ''}`));
    if (infos > 0)
        parts.push(chalk_1.default.cyan(`${infos} info`));
    if (parts.length === 0) {
        lines.push(chalk_1.default.green('No violations found'));
    }
    else {
        lines.push(parts.join(', '));
    }
    return lines.join('\n');
}
//# sourceMappingURL=tty.js.map