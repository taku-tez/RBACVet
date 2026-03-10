import chalk from 'chalk';
import type { Violation, Rule } from '../rules/types';
import type { ServiceAccountScore } from '../engine/scorer';

const SEVERITY_COLOR = {
  error: chalk.red,
  warning: chalk.yellow,
  info: chalk.cyan,
};

const LEVEL_COLOR = {
  CRITICAL: chalk.bgRed.white.bold,
  HIGH: chalk.red.bold,
  MEDIUM: chalk.yellow.bold,
  LOW: chalk.green,
};

function pad(s: string, len: number): string {
  return s.padEnd(len);
}

export function formatTTY(
  violations: Violation[],
  scores: ServiceAccountScore[],
  useColor: boolean,
  ruleMap?: Map<string, Rule>,
): string {
  if (!useColor) {
    chalk.level = 0;
  }

  const lines: string[] = [];

  // Group violations by file
  const byFile = new Map<string, Violation[]>();
  for (const v of violations) {
    const existing = byFile.get(v.file) || [];
    existing.push(v);
    byFile.set(v.file, existing);
  }

  for (const [file, fileViolations] of byFile) {
    lines.push(chalk.underline(file));
    for (const v of fileViolations) {
      const colorFn = SEVERITY_COLOR[v.severity] || chalk.white;
      const severityStr = colorFn(pad(v.severity, 7));
      const cisId = ruleMap?.get(v.rule)?.cisId;
      const ruleLabel = cisId ? `${v.rule}(${cisId})` : v.rule;
      const ruleStr = chalk.bold(pad(ruleLabel, 18));
      const resource = chalk.dim(pad(v.resource, 40));
      lines.push(`  ${ruleStr}  ${severityStr}  ${resource}  ${v.message}`);
    }
    lines.push('');
  }

  // Risk scores
  if (scores.length > 0) {
    lines.push(chalk.bold('Risk Scores:'));
    for (const s of scores) {
      if (s.score === 0) continue;
      const levelFn = LEVEL_COLOR[s.level] || chalk.white;
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

  const parts: string[] = [];
  if (errors > 0) parts.push(chalk.red(`${errors} error${errors !== 1 ? 's' : ''}`));
  if (warnings > 0) parts.push(chalk.yellow(`${warnings} warning${warnings !== 1 ? 's' : ''}`));
  if (infos > 0) parts.push(chalk.cyan(`${infos} info`));

  if (parts.length === 0) {
    lines.push(chalk.green('No violations found'));
  } else {
    lines.push(parts.join(', '));
  }

  return lines.join('\n');
}
