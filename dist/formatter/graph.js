"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.formatGraphSummary = formatGraphSummary;
const chalk_1 = __importDefault(require("chalk"));
function formatGraphSummary(graph, paths, useColor) {
    if (!useColor)
        chalk_1.default.level = 0;
    const lines = [];
    lines.push(chalk_1.default.bold('Privilege Escalation Graph Summary'));
    lines.push('');
    const saCount = [...graph.nodes.values()].filter(n => n.kind === 'ServiceAccount').length;
    const roleCount = [...graph.nodes.values()].filter(n => n.kind === 'Role' || n.kind === 'ClusterRole').length;
    lines.push(`  ${saCount} ServiceAccounts, ${roleCount} Roles, ${graph.edges.length} edges`);
    lines.push('');
    if (paths.length === 0) {
        lines.push(chalk_1.default.green('  No privilege escalation paths found'));
    }
    else {
        lines.push(chalk_1.default.red.bold(`  ${paths.length} escalation path${paths.length !== 1 ? 's' : ''} found:`));
        lines.push('');
        for (const p of paths) {
            const saLabel = `ServiceAccount/${p.serviceAccount.namespace}/${p.serviceAccount.name}`;
            const pathStr = p.path.map(n => `${n.kind}/${n.name}`).join(' → ');
            const risk = p.riskLevel ? ` [${p.riskLevel}]` : '';
            const score = p.score !== undefined ? ` ${p.score}/100` : '';
            lines.push(`  ${chalk_1.default.bold(saLabel)}${chalk_1.default.dim(score)}${risk}`);
            lines.push(`    ${chalk_1.default.dim(pathStr)}`);
            lines.push('');
        }
    }
    if (graph.cycles.length > 0) {
        lines.push(chalk_1.default.yellow.bold(`  ${graph.cycles.length} cycle${graph.cycles.length !== 1 ? 's' : ''} detected:`));
        for (const cycle of graph.cycles) {
            lines.push(`    ${cycle.join(' → ')} → ${cycle[0]}`);
        }
        lines.push('');
    }
    return lines.join('\n');
}
//# sourceMappingURL=graph.js.map