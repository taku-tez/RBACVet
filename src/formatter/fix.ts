import chalk from 'chalk';
import type { FixResult, FixSuggestion } from '../fix/types';

export function formatFixTTY(result: FixResult, useColor: boolean): string {
  if (!useColor) chalk.level = 0;

  const lines: string[] = [];

  if (result.suggestions.length === 0) {
    lines.push(chalk.dim('No fix suggestions available for current violations.'));
    return lines.join('\n');
  }

  lines.push(chalk.bold(`\nFix Suggestions (${result.suggestions.length})${result.llmUsed ? ' — LLM-enhanced' : ''}:`));
  lines.push('');

  for (const s of result.suggestions) {
    const sourceTag = s.source === 'llm' ? chalk.magenta('[LLM]') : chalk.dim('[rule-based]');
    const autoTag = s.autoApplicable ? chalk.green('[auto-applicable]') : chalk.yellow('[manual]');

    lines.push(`  ${chalk.bold(s.ruleId)}  ${sourceTag} ${autoTag}`);
    lines.push(`  ${chalk.dim(s.violation.resource)}`);
    lines.push(`  ${s.explanation}`);
    lines.push('');
    lines.push(chalk.bold('  Suggested patch:'));
    for (const patchLine of s.yamlPatch.split('\n')) {
      lines.push(`    ${chalk.cyan(patchLine)}`);
    }
    lines.push('');
  }

  if (result.errors.length > 0) {
    lines.push(chalk.yellow('Fix generation errors:'));
    for (const e of result.errors) {
      lines.push(`  ${chalk.yellow(e.message)}`);
    }
  }

  const autoCount = result.suggestions.filter(s => s.autoApplicable).length;
  if (autoCount > 0) {
    lines.push(chalk.dim(`Run with --apply-fixes to automatically apply ${autoCount} fix${autoCount !== 1 ? 'es' : ''}.`));
  }

  return lines.join('\n');
}

export function fixSuggestionsToJSON(result: FixResult): object[] {
  return result.suggestions.map(s => ({
    ruleId: s.ruleId,
    source: s.source,
    resource: s.violation.resource,
    explanation: s.explanation,
    yamlPatch: s.yamlPatch,
    autoApplicable: s.autoApplicable,
    patchTarget: s.patchTarget,
  }));
}
