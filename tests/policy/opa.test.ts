import { describe, it, expect } from 'vitest';
import { isOPAAvailable, runOPAPolicy } from '../../src/policy/opa';
import type { ResourceGraph } from '../../src/rules/types';

const emptyGraph: ResourceGraph = {
  roles: new Map(),
  clusterRoles: new Map(),
  roleBindings: [],
  clusterRoleBindings: [],
  serviceAccounts: new Map(),
  authorizationPolicies: [],
};

describe('OPA module exports', () => {
  it('exports isOPAAvailable as a function', () => {
    expect(typeof isOPAAvailable).toBe('function');
    expect(typeof runOPAPolicy).toBe('function');
  });
});

describe('runOPAPolicy error paths', () => {
  it('throws when rego file does not exist', async () => {
    await expect(
      runOPAPolicy('/nonexistent/policy.rego', [], emptyGraph)
    ).rejects.toThrow('Rego policy file not found');
  });
});

describe('isOPAAvailable', () => {
  it('returns a boolean', () => {
    const result = isOPAAvailable();
    expect(typeof result).toBe('boolean');
  });
});
