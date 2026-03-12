import { RB1_RULES } from './rb1/least-privilege';
import { RB2_RULES } from './rb2/privilege-escalation';
import { RB3_RULES } from './rb3/secret-access';
import { RB4_RULES } from './rb4/serviceaccount';
import { RB5_RULES } from './rb5/cluster-risks';
import { RB6_RULES } from './rb6/cross-namespace';
import { RB7_RULES } from './rb7/admission-webhooks';
import { RB8_RULES } from './rb8/workload-risks';
import { RB9_RULES } from './rb9/node-security';
import { IS1_RULES } from './is1/istio';
import type { Rule } from './types';

export const ALL_RULES: Rule[] = [
  ...RB1_RULES,
  ...RB2_RULES,
  ...RB3_RULES,
  ...RB4_RULES,
  ...RB5_RULES,
  ...RB6_RULES,
  ...RB7_RULES,
  ...RB8_RULES,
  ...RB9_RULES,
  ...IS1_RULES,
];

export const RULE_MAP = new Map<string, Rule>(
  ALL_RULES.map(r => [r.id, r])
);
