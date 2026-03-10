import * as fs from 'fs';
import * as path from 'path';
import { parseFile } from '../parser/parser';
import type { FixSuggestion } from './types';

export interface ApplyResult {
  file: string;
  applied: number;
  skipped: number;
  errors: string[];
}

function findDocumentEnd(lines: string[], startLine: number): number {
  // startLine is 1-based; find the next --- separator or EOF
  for (let i = startLine; i < lines.length; i++) {
    if (lines[i].match(/^---\s*$/)) return i; // 0-based exclusive end
  }
  return lines.length;
}

function applyRB4001Fix(lines: string[], startLine: number, endLine: number): string[] {
  const result = [...lines];
  // Find and replace automountServiceAccountToken line, or insert before last non-empty line of doc
  let found = false;
  for (let i = startLine - 1; i < endLine; i++) {
    if (result[i].match(/^\s*automountServiceAccountToken:/)) {
      result[i] = 'automountServiceAccountToken: false';
      found = true;
      break;
    }
  }
  if (!found) {
    // Insert after the metadata block (after the last metadata field before rules/spec)
    let insertAt = endLine - 1;
    for (let i = startLine - 1; i < endLine; i++) {
      if (result[i].match(/^(rules:|spec:|stringData:|data:)/)) {
        insertAt = i;
        break;
      }
    }
    result.splice(insertAt, 0, 'automountServiceAccountToken: false');
  }
  return result;
}

function applyRulesBlockFix(lines: string[], startLine: number, endLine: number, patch: string): string[] {
  const result = [...lines];
  // Find the 'rules:' line within the document
  let rulesStart = -1;
  for (let i = startLine - 1; i < endLine; i++) {
    if (result[i].match(/^rules:/)) {
      rulesStart = i;
      break;
    }
  }
  if (rulesStart === -1) return lines; // Can't find rules block

  // Find end of rules block (next top-level key or end of doc)
  let rulesEnd = endLine;
  for (let i = rulesStart + 1; i < endLine; i++) {
    if (result[i].match(/^[a-zA-Z]/) && !result[i].match(/^-/)) {
      rulesEnd = i;
      break;
    }
  }

  const patchLines = patch.split('\n');
  result.splice(rulesStart, rulesEnd - rulesStart, ...patchLines);
  return result;
}

export function generateDiff(original: string[], patched: string[], file: string): string {
  const lines: string[] = [`--- a/${file}`, `+++ b/${file}`];
  let i = 0, j = 0;
  while (i < original.length || j < patched.length) {
    const orig = original[i];
    const patch = patched[j];
    if (orig === patch) {
      lines.push(` ${orig}`);
      i++; j++;
    } else if (orig !== undefined && patch === undefined) {
      lines.push(`-${orig}`);
      i++;
    } else if (orig === undefined && patch !== undefined) {
      lines.push(`+${patch}`);
      j++;
    } else {
      lines.push(`-${orig}`);
      lines.push(`+${patch}`);
      i++; j++;
    }
  }
  return lines.join('\n');
}

export async function applyFixes(
  suggestions: FixSuggestion[],
  dryRun: boolean,
): Promise<ApplyResult[]> {
  const byFile = new Map<string, FixSuggestion[]>();
  for (const s of suggestions) {
    if (!s.autoApplicable) continue;
    const existing = byFile.get(s.patchTarget.file) ?? [];
    existing.push(s);
    byFile.set(s.patchTarget.file, existing);
  }

  const results: ApplyResult[] = [];

  for (const [file, fileSuggestions] of byFile) {
    const result: ApplyResult = { file, applied: 0, skipped: 0, errors: [] };

    if (!fs.existsSync(file) || file === 'test.yaml' || file === '<cluster>') {
      result.errors.push(`Cannot apply to ${file}`);
      results.push(result);
      continue;
    }

    const content = fs.readFileSync(file, 'utf-8');
    let lines = content.split('\n');

    // Apply in reverse order to preserve line numbers
    const sorted = [...fileSuggestions].sort((a, b) => b.patchTarget.startLine - a.patchTarget.startLine);

    for (const suggestion of sorted) {
      const { startLine } = suggestion.patchTarget;
      const endLine = findDocumentEnd(lines, startLine);

      try {
        let patched: string[];
        if (suggestion.ruleId === 'RB4001') {
          patched = applyRB4001Fix(lines, startLine, endLine);
        } else {
          patched = applyRulesBlockFix(lines, startLine, endLine, suggestion.yamlPatch);
        }

        if (dryRun) {
          console.log(generateDiff(lines, patched, file));
        } else {
          lines = patched;
        }
        result.applied++;
      } catch (e) {
        result.skipped++;
        result.errors.push(`${suggestion.ruleId}: ${(e as Error).message}`);
      }
    }

    if (!dryRun && result.applied > 0) {
      const newContent = lines.join('\n');
      // Verify parses cleanly
      const parseResult = parseFile(newContent, file);
      if (parseResult.errors.length > 0) {
        result.errors.push(`Parse validation failed after applying fixes: ${parseResult.errors[0].message}`);
        result.applied = 0;
      } else {
        const tmpPath = `${file}.rbacvet.tmp`;
        fs.writeFileSync(tmpPath, newContent, 'utf-8');
        fs.renameSync(tmpPath, file);
      }
    }

    results.push(result);
  }

  return results;
}
