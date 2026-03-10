import chalk from 'chalk';
import type { DiffEntry } from '../cluster/diff';

export function formatDiff(entries: DiffEntry[], useColor: boolean): string {
  if (!useColor) chalk.level = 0;

  if (entries.length === 0) {
    return chalk.green('No differences found — cluster matches local manifests');
  }

  const lines: string[] = [];

  for (const entry of entries) {
    const ns = entry.namespace ? `${entry.namespace}/` : '';
    const label = `${entry.kind}/${ns}${entry.name}`;

    switch (entry.status) {
      case 'added':
        lines.push(chalk.green(`+ ${label}  [only in local manifests — not in cluster]`));
        break;
      case 'removed':
        lines.push(chalk.red(`- ${label}  [only in cluster — not in local manifests]`));
        break;
      case 'changed':
        lines.push(chalk.yellow(`~ ${label}  [changed]`));
        if (entry.changes) {
          for (const ch of entry.changes) {
            lines.push(chalk.dim(`    cluster: ${JSON.stringify(ch.clusterValue)}`));
            lines.push(chalk.dim(`    local:   ${JSON.stringify(ch.localValue)}`));
          }
        }
        break;
    }
  }

  lines.push('');
  const added = entries.filter(e => e.status === 'added').length;
  const removed = entries.filter(e => e.status === 'removed').length;
  const changed = entries.filter(e => e.status === 'changed').length;
  const parts: string[] = [];
  if (added > 0) parts.push(chalk.green(`${added} added`));
  if (removed > 0) parts.push(chalk.red(`${removed} removed`));
  if (changed > 0) parts.push(chalk.yellow(`${changed} changed`));
  lines.push(parts.join(', '));

  return lines.join('\n');
}
