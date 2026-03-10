import * as fs from 'fs';
import * as path from 'path';
import * as yaml from 'js-yaml';
import type { PolicyFile, PolicyExemption } from './types';

function validateExemption(e: unknown, index: number): PolicyExemption {
  const ex = e as Record<string, unknown>;
  if (!ex.rule || typeof ex.rule !== 'string') throw new Error(`exemptions[${index}].rule is required`);
  if (!ex.resource || typeof ex.resource !== 'string') throw new Error(`exemptions[${index}].resource is required`);
  if (!ex.reason || typeof ex.reason !== 'string') throw new Error(`exemptions[${index}].reason is required`);
  if (!ex.author || typeof ex.author !== 'string') throw new Error(`exemptions[${index}].author is required`);
  if (ex.expires && typeof ex.expires !== 'string') throw new Error(`exemptions[${index}].expires must be a string`);
  if (ex.expires && isNaN(Date.parse(ex.expires as string))) {
    throw new Error(`exemptions[${index}].expires must be a valid ISO date`);
  }
  return {
    rule: ex.rule as string,
    resource: ex.resource as string,
    reason: ex.reason as string,
    author: ex.author as string,
    expires: ex.expires as string | undefined,
  };
}

export function validatePolicy(raw: unknown): PolicyFile {
  const obj = raw as Record<string, unknown>;
  if (!obj.version) throw new Error('policy file missing "version" field');
  if (!Array.isArray(obj.exemptions)) throw new Error('policy file missing "exemptions" array');
  return {
    version: String(obj.version),
    exemptions: obj.exemptions.map((e, i) => validateExemption(e, i)),
  };
}

export function loadPolicy(policyPath?: string): PolicyFile | null {
  const searchPaths = policyPath
    ? [policyPath]
    : [
        path.join(process.cwd(), '.rbacvet-policy.yaml'),
        path.join(process.cwd(), '.rbacvet-policy.yml'),
      ];

  for (const p of searchPaths) {
    if (fs.existsSync(p)) {
      try {
        const content = fs.readFileSync(p, 'utf-8');
        const raw = yaml.load(content);
        return validatePolicy(raw);
      } catch (e) {
        console.error(`Warning: failed to load policy file ${p}: ${(e as Error).message}`);
      }
    }
  }

  return null;
}
