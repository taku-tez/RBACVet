import type { Role, RoleBinding, ServiceAccount, AuthorizationPolicy } from '../parser/types';
import type { RBACVetConfig } from '../engine/config';

export type Severity = 'error' | 'warning' | 'info';

export interface Violation {
  rule: string;
  severity: Severity;
  message: string;
  resource: string;
  file: string;
  line: number;
}

export interface ResourceGraph {
  roles: Map<string, Role>;
  clusterRoles: Map<string, Role>;
  roleBindings: RoleBinding[];
  clusterRoleBindings: RoleBinding[];
  serviceAccounts: Map<string, ServiceAccount>;
  authorizationPolicies: AuthorizationPolicy[];
}

export interface RuleContext {
  graph: ResourceGraph;
  config: RBACVetConfig;
}

export interface Rule {
  id: string;
  severity: Severity;
  description: string;
  url?: string;
  cisId?: string;
  check(ctx: RuleContext): Violation[];
}
