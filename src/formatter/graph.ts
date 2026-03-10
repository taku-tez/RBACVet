import chalk from 'chalk';
import type { EscalationGraph } from '../graph/builder';
import type { EscalationPath } from '../graph/paths';

export function formatGraphSummary(
  graph: EscalationGraph,
  paths: EscalationPath[],
  useColor: boolean,
): string {
  if (!useColor) chalk.level = 0;

  const lines: string[] = [];

  lines.push(chalk.bold('Privilege Escalation Graph Summary'));
  lines.push('');

  const saCount = [...graph.nodes.values()].filter(n => n.kind === 'ServiceAccount').length;
  const roleCount = [...graph.nodes.values()].filter(n => n.kind === 'Role' || n.kind === 'ClusterRole').length;
  lines.push(`  ${saCount} ServiceAccounts, ${roleCount} Roles, ${graph.edges.length} edges`);
  lines.push('');

  if (paths.length === 0) {
    lines.push(chalk.green('  No privilege escalation paths found'));
  } else {
    lines.push(chalk.red.bold(`  ${paths.length} escalation path${paths.length !== 1 ? 's' : ''} found:`));
    lines.push('');

    for (const p of paths) {
      const saLabel = `ServiceAccount/${p.serviceAccount.namespace}/${p.serviceAccount.name}`;
      const pathStr = p.path.map(n => `${n.kind}/${n.name}`).join(' → ');
      const risk = p.riskLevel ? ` [${p.riskLevel}]` : '';
      const score = p.score !== undefined ? ` ${p.score}/100` : '';
      lines.push(`  ${chalk.bold(saLabel)}${chalk.dim(score)}${risk}`);
      lines.push(`    ${chalk.dim(pathStr)}`);
      lines.push('');
    }
  }

  if (graph.cycles.length > 0) {
    lines.push(chalk.yellow.bold(`  ${graph.cycles.length} cycle${graph.cycles.length !== 1 ? 's' : ''} detected:`));
    for (const cycle of graph.cycles) {
      lines.push(`    ${cycle.join(' → ')} → ${cycle[0]}`);
    }
    lines.push('');
  }

  return lines.join('\n');
}
