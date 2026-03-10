import type { Violation } from '../rules/types';

export interface PolicyExemption {
  rule: string;
  resource: string;
  reason: string;
  author: string;
  expires?: string;
}

export interface PolicyFile {
  version: string;
  exemptions: PolicyExemption[];
}

export interface ResolvedExemption extends PolicyExemption {
  isExpired: boolean;
  daysUntilExpiry?: number;
}

export interface FilterResult {
  remaining: Violation[];
  exempted: Array<{ violation: Violation; exemption: ResolvedExemption }>;
  expiredExemptions: ResolvedExemption[];
}
