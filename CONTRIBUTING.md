# Contributing to RBACVet

## Setup

```bash
git clone https://github.com/RBACVet/rbacvet
cd rbacvet
npm install
npm test          # run all 521 tests
npm run lint      # TypeScript type check
```

## Project structure

```
src/
  parser/         # YAML → internal types (parser.ts, types.ts)
  rules/          # All detection rules
    rb1/          # Least privilege violations
    rb2/          # Privilege escalation paths
    rb3/          # Secret & data access
    rb4/          # ServiceAccount design
    rb5/          # Cluster-level risks
    rb6/          # Cross-namespace & network
    rb7/          # Admission & runtime control
    rb8/          # Workload risks
    rb9/          # Node & resource control
    is1/          # Istio AuthorizationPolicy
    index.ts      # ALL_RULES, RULE_MAP exports
    types.ts      # Rule, Violation, ResourceGraph interfaces
    utils.ts      # hasWildcard, hasVerb, WRITE_VERBS, etc.
    cis.ts        # enrichViolationsWithCIS()
  engine/         # analyzer.ts, scorer.ts, config.ts
  fix/            # YAML patch generation
    rule-fixes.ts # RULE_FIX_MAP, generateRuleFixes()
    llm-client.ts # Anthropic API integration
    applier.ts    # Atomic file writes
  formatter/      # tty.ts, json.ts, sarif.ts, html.ts
  cluster/        # K8s API client (fetcher.ts, converter.ts, diff.ts)
  graph/          # Privilege escalation graph (builder.ts, dot.ts, paths.ts)
  policy/         # Exemption loading and filtering
  notify/         # Slack/webhook integration
  schedule/       # Periodic scan runner
  index.ts        # CLI entry point

tests/
  rules/          # Per-category rule tests (rb1.test.ts … rb9.test.ts, is1.test.ts)
  fix/            # Fix function tests (rule-fixes.test.ts)
  rules/cis.test.ts   # CIS ID coverage tests
  integration.test.ts # End-to-end fixture tests
  helpers.ts      # makeRole, makeClusterRole, makeBinding, etc.
  fixtures/       # YAML fixtures (clean/ and violations/)
```

## Adding a new rule

### 1. Choose a category

| Prefix | Category | File |
|--------|----------|------|
| RB1 | Least privilege | `src/rules/rb1/least-privilege.ts` |
| RB2 | Privilege escalation | `src/rules/rb2/privilege-escalation.ts` |
| RB3 | Secret & data access | `src/rules/rb3/secret-access.ts` |
| RB4 | ServiceAccount design | `src/rules/rb4/serviceaccount.ts` |
| RB5 | Cluster-level risks | `src/rules/rb5/cluster-risks.ts` |
| RB6 | Cross-namespace & network | `src/rules/rb6/cross-namespace.ts` |
| RB7 | Admission & runtime | `src/rules/rb7/admission-webhooks.ts` |
| RB8 | Workload risks | `src/rules/rb8/workload-risks.ts` |
| RB9 | Node & resource control | `src/rules/rb9/node-security.ts` |
| IS1 | Istio AuthorizationPolicy | `src/rules/is1/istio.ts` |

### 2. Implement the rule

```typescript
// src/rules/rbN/my-category.ts
import type { Rule, RuleContext, Violation } from '../types';
import { hasAnyVerb, hasResource, resourceLabel, WRITE_VERBS } from '../utils';

export const RBN001: Rule = {
  id: 'RBN001',
  severity: 'high',            // critical | high | medium | low | info
  description: 'Short description of the risk',
  cisId: 'CIS 5.1.3',         // optional — add if mapped to CIS Benchmark
  check(ctx: RuleContext): Violation[] {
    const violations: Violation[] = [];
    for (const role of [...ctx.graph.roles.values(), ...ctx.graph.clusterRoles.values()]) {
      for (const rule of role.rules) {
        if (hasResource(rule, 'target-resource') && hasAnyVerb(rule, WRITE_VERBS)) {
          violations.push({
            rule: 'RBN001',
            severity: 'high',
            message: `${resourceLabel(role)} can write target-resource — explain impact here`,
            resource: resourceLabel(role),
            file: role.sourceFile,
            line: role.sourceLine,
          });
          break;
        }
      }
    }
    return violations;
  },
};
```

### 3. Export from the category file

```typescript
export const RBN_RULES: Rule[] = [...existingRules, RBN001];
```

### 4. Register in `src/rules/index.ts`

```typescript
import { RBN_RULES } from './rbn/my-category';
// ...
export const ALL_RULES: Rule[] = [
  ...existing,
  ...RBN_RULES,
];
```

### 5. Write tests

Create or extend `tests/rules/rbN.test.ts`:

```typescript
import { describe, it, expect } from 'vitest';
import { hasViolation, makeClusterRole, analyzeResources2 } from '../helpers';

describe('RBN001 - target-resource write', () => {
  it('flags write access', () => {
    const { violations } = analyzeResources2([
      makeClusterRole('writer', [{ apiGroups: [''], resources: ['target-resource'], verbs: ['update'] }]),
    ]);
    expect(hasViolation(violations, 'RBN001')).toBe(true);
  });

  it('does not flag read-only access', () => {
    const { violations } = analyzeResources2([
      makeClusterRole('reader', [{ apiGroups: [''], resources: ['target-resource'], verbs: ['get'] }]),
    ]);
    expect(hasViolation(violations, 'RBN001')).toBe(false);
  });

  it('severity is high', () => {
    const { violations } = analyzeResources2([
      makeClusterRole('writer', [{ apiGroups: [''], resources: ['target-resource'], verbs: ['update'] }]),
    ]);
    expect(violations.find(v => v.rule === 'RBN001')?.severity).toBe('high');
  });
});
```

### 6. Add a fix (optional but encouraged)

In `src/fix/rule-fixes.ts`:

```typescript
const EXPLANATIONS = {
  // ...
  RBN001: {
    en: 'English explanation of how to fix this.',
    ja: '日本語の修正説明。',
  },
};

const RBN001Fix: RuleFixFn = (violation, graph, lang) => {
  const role = findRole(violation.resource, graph);
  if (!role) return null;
  // Use helpers: removeResourceFromRules, restrictVerbsToReadOnly, removeVerbFromRules, patchRules
  const patch = restrictVerbsToReadOnly(role.rules, 'target-resource');
  return {
    violation, ruleId: 'RBN001', source: 'rule-based',
    explanation: EXPLANATIONS.RBN001[lang],
    yamlPatch: patch,
    autoApplicable: false,   // true only if the patch is always safe to apply
    patchTarget: { file: violation.file, startLine: violation.line, endLine: violation.line + 30 },
  };
};

// Add to RULE_FIX_MAP:
export const RULE_FIX_MAP = new Map<string, RuleFixFn>([
  // ...
  ['RBN001', RBN001Fix],
]);
```

Then add test coverage in `tests/fix/rule-fixes.test.ts`:
1. Add `'RBN001'` to the `expectedRules` array.
2. Add a `describe('RBN001 fix', ...)` block.

### 7. Add CIS mapping (if applicable)

In `tests/rules/cis.test.ts`, add an assertion:

```typescript
it('RULE_MAP has cisId on RBN001 (CIS 5.1.X)', () => {
  expect(RULE_MAP.get('RBN001')?.cisId).toBe('CIS 5.1.X');
});
```

### 8. Update README.md

Add a row to the appropriate rule table and update the total count.

---

## Severity guidelines

| Severity | Use when |
|----------|----------|
| critical | Immediate cluster compromise possible (cluster-admin binding, unauthenticated access, etcd access) |
| high | Privilege escalation possible, or direct secret/exec access |
| medium | Indirect risk, excess permissions, or defense-in-depth violation |
| low | Hygiene issue with limited direct security impact |
| info | Informational — may be intentional, good for audits |

## Key utilities (`src/rules/utils.ts`)

| Function | Description |
|----------|-------------|
| `WRITE_VERBS` | `['create', 'update', 'patch', 'delete', 'deletecollection', '*']` |
| `hasWildcard(arr)` | Returns true if array contains `"*"` |
| `hasVerb(rule, verb)` | Returns true if rule.verbs includes `verb` |
| `hasAnyVerb(rule, verbs)` | Returns true if rule.verbs overlaps with `verbs` |
| `hasResource(rule, res)` | Returns true if rule.resources includes `res` or `"*"` |
| `resourceLabel(role)` | Returns `"ClusterRole/name"` or `"Role/ns/name"` |

## Running tests

```bash
npm test                          # run all tests
npm test -- tests/rules/rb9.test.ts   # single file
npm run test:watch                # watch mode
npm run lint                      # TypeScript check (src only)
npm run lint:tests                # TypeScript check (tests + src)
```

All PRs must pass `npm test` with no new failures.

## Commit style

```
feat: add RBN001 — target-resource write detection
fix: RBN001 false positive when apiGroup is not core
test: add RBN001 fix coverage
docs: add RBN001 to README rule table
```
