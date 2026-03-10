import type { Violation } from '../rules/types';

export type FixSource = 'rule-based' | 'llm';
export type FixLang = 'en' | 'ja';

export interface FixSuggestion {
  violation: Violation;
  ruleId: string;
  source: FixSource;
  explanation: string;
  yamlPatch: string;
  autoApplicable: boolean;
  patchTarget: {
    file: string;
    startLine: number;
    endLine: number;
  };
}

export interface FixResult {
  suggestions: FixSuggestion[];
  llmUsed: boolean;
  errors: Array<{ ruleId: string; message: string }>;
}
