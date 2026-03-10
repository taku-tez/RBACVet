import chalk from 'chalk';
import type { EnvCompareResult } from '../cluster/compare';

export function formatCompare(result: EnvCompareResult, useColor: boolean): string {
  if (!useColor) chalk.level = 0;

  const lines: string[] = [];

  lines.push(chalk.bold(`Comparing ${result.contextA} → ${result.contextB}`));
  lines.push('');

  const newViolations = result.violationDeltas.filter(d => d.status === 'new');
  const fixedViolations = result.violationDeltas.filter(d => d.status === 'fixed');

  if (newViolations.length > 0) {
    lines.push(chalk.red.bold('NEW violations (regressions):'));
    for (const d of newViolations) {
      const v = d.violation;
      lines.push(chalk.red(`  + [${v.rule}] ${v.resource}  ${v.message}`));
    }
    lines.push('');
  }

  if (fixedViolations.length > 0) {
    lines.push(chalk.green.bold('FIXED violations (improvements):'));
    for (const d of fixedViolations) {
      const v = d.violation;
      lines.push(chalk.green(`  - [${v.rule}] ${v.resource}  ${v.message}`));
    }
    lines.push('');
  }

  if (result.scoreDeltas.length > 0) {
    lines.push(chalk.bold('Score changes:'));
    for (const sd of result.scoreDeltas) {
      const arrow = sd.delta > 0 ? chalk.red(`+${sd.delta}`) : chalk.green(`${sd.delta}`);
      lines.push(`  ${sd.name}  ${sd.scoreA} → ${sd.scoreB}  (${arrow})  ${sd.levelA} → ${sd.levelB}`);
    }
    lines.push('');
  }

  // Summary
  const parts: string[] = [];
  if (result.newCount > 0) {
    parts.push(chalk.red(`${result.newCount} new`));
  }
  if (result.fixedCount > 0) {
    parts.push(chalk.green(`${result.fixedCount} fixed`));
  }
  const shared = result.violationDeltas.filter(d => d.status === 'shared').length;
  if (shared > 0) {
    parts.push(chalk.dim(`${shared} shared`));
  }

  if (parts.length === 0) {
    lines.push(chalk.green('No differences in violations'));
  } else {
    lines.push(parts.join(', '));
  }

  return lines.join('\n');
}

export function formatCompareJSON(result: EnvCompareResult): string {
  return JSON.stringify(result, null, 2);
}
