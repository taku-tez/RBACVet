# RBACVet

Kubernetes RBAC security analyzer. Detects over-privileged roles, privilege escalation paths, and dangerous permission bindings — with risk scoring, fix suggestions, and CI integration.

```
$ rbacvet --dir ./rbac/

rbac/admin-role.yaml
  RB1001  high      ClusterRole/admin-role         wildcard verbs on all resources
  RB2001  critical  ClusterRoleBinding/admin-bind   binds to cluster-admin
  RB3001  high      Role/app-role                  grants read access to secrets

rbac/service-accounts.yaml
  RB4001  info      ServiceAccount/api-server      automountServiceAccountToken not disabled

Risk Score: ServiceAccount/api-server → 87/100  [CRITICAL]
Privilege escalation path: api-server → admin-role → cluster-admin

3 errors, 1 warning — exit code 2
```

## Installation

```bash
npm install -g rbacvet
```

## Usage

```bash
# Scan RBAC manifest files
rbacvet role.yaml rolebinding.yaml serviceaccount.yaml

# Scan a directory recursively
rbacvet --dir ./rbac/

# Live cluster scan (uses current kubeconfig)
rbacvet --cluster
rbacvet --cluster --namespace production
rbacvet --cluster --all-namespaces

# Target a specific kubeconfig context
rbacvet --cluster --context staging

# Compare cluster state vs local manifests
rbacvet --diff --cluster --dir ./rbac/

# Scan from GitHub
rbacvet --github owner/repo
```

### Output formats

```bash
rbacvet --format tty   --dir ./rbac/   # colored terminal (default)
rbacvet --format json  --dir ./rbac/   # structured JSON with risk scores
rbacvet --format sarif --dir ./rbac/   # SARIF 2.1 (GitHub code scanning)
rbacvet --format html  --dir ./rbac/   # self-contained interactive HTML report
```

### Privilege escalation graph

```bash
rbacvet --map --dir ./rbac/                      # DOT format (Graphviz)
rbacvet --map --map-format json --cluster        # JSON escalation paths
rbacvet --map --map-format json --cluster | jq '.escalationPaths'
```

### Fix suggestions

```bash
rbacvet --fix --dir ./rbac/              # show rule-based YAML patches
rbacvet --fix --fix-lang ja --dir ./rbac/  # Japanese explanations
rbacvet --apply-fixes --dir ./rbac/      # write patches to source files
rbacvet --apply-fixes --dry-run --dir ./rbac/  # preview without writing
```

### CI / utility commands

```bash
rbacvet --init-ci github    # generate .github/workflows/rbacvet.yml
rbacvet --init-ci gitlab    # generate .gitlab-ci.yml
rbacvet --list-rules        # list all rules with severity and CIS IDs
rbacvet --explain RB2001    # detailed explanation of a specific rule
```

### Advanced options

```bash
# Filtering
rbacvet --severity high --dir ./rbac/          # only high+ violations
rbacvet --ignore RB4007,RB5005 --dir ./rbac/   # skip specific rules
rbacvet --rule RB2001 --dir ./rbac/            # run a single rule

# Policy-based exemptions
rbacvet --policy ./exemptions.yaml --dir ./rbac/

# Scheduled cluster scans
rbacvet --schedule 1h --cluster                # scan every hour

# Slack / webhook notifications
rbacvet --notify https://hooks.slack.com/... --cluster

# Compare two kubeconfig contexts
rbacvet --compare-context prod --cluster --context staging

# OPA/Rego custom policies
rbacvet --opa ./policies/ --dir ./rbac/

# Set risk score threshold for CI failure
rbacvet --risk-threshold 60 --dir ./rbac/
```

## Rules

74 rules across 10 categories. Run `rbacvet --list-rules` for live output.

### Severity levels

| Severity | Exit code | Score weight | SARIF level |
|----------|-----------|--------------|-------------|
| critical | 2         | +25          | error       |
| high     | 2         | +15          | error       |
| medium   | 1         | +5           | warning     |
| low      | 1         | +2           | note        |
| info     | 0         | +0           | note        |

---

### RB1xxx — Least Privilege Violations (14 rules)

| ID | Severity | CIS | Description |
|----|----------|-----|-------------|
| RB1001 | high | 5.1.3 | Wildcard `*` in verbs |
| RB1002 | critical | 5.1.3 | Wildcard `*` in resources |
| RB1003 | medium | 5.1.3 | Wildcard `*` in apiGroups |
| RB1004 | high | 5.1.3 | `create` + `delete` combined on same resource |
| RB1005 | medium | | `update` + `patch` combined with no resource restriction |
| RB1006 | high | 5.1.3 | ClusterRole with write access to all core resources |
| RB1007 | info | | Role grants `list` on all resources |
| RB1008 | info | | Role grants `watch` on all resources |
| RB1009 | high | 5.1.3 | Role with `*` verbs on `nodes` resource |
| RB1010 | high | 5.1.3 | Role with `*` verbs on `namespaces` resource |
| RB1011 | medium | | Role with `deletecollection` verb |
| RB1012 | info | | Role with more than 20 permission rules |
| RB1013 | info | | Role has write-only access — likely misconfiguration |
| RB1014 | high | | Role grants write access to `pods/ephemeralcontainers` |

### RB2xxx — Privilege Escalation Paths (12 rules)

| ID | Severity | CIS | Description |
|----|----------|-----|-------------|
| RB2001 | critical | 5.1.1 | ClusterRoleBinding binds to `cluster-admin` |
| RB2002 | critical | 5.1.8 | Role with `escalate` verb |
| RB2003 | high | 5.1.8 | Role with `bind` verb |
| RB2004 | high | 5.1.8 | Role can modify Role/ClusterRole (RBAC management) |
| RB2005 | high | 5.1.8 | Role can modify RoleBinding/ClusterRoleBinding |
| RB2006 | high | 5.1.8 | Impersonation permissions (users, groups, serviceaccounts) |
| RB2007 | high | 5.1.8 | Role grants access to `tokenreviews` or `subjectaccessreviews` |
| RB2008 | medium | | Role can create/update `ValidatingWebhookConfiguration` |
| RB2009 | medium | | Role can create/update `MutatingWebhookConfiguration` |
| RB2010 | high | 5.1.1 | Detected privilege escalation chain (A → B → cluster-admin) |
| RB2011 | medium | 5.1.3 | Role grants write access to `ValidatingAdmissionPolicies` (K8s 1.26+) |
| RB2012 | high | 5.1.8 | Role can approve CertificateSigningRequests — allows issuing arbitrary certs |

### RB3xxx — Secret & Data Access (12 rules)

| ID | Severity | CIS | Description |
|----|----------|-----|-------------|
| RB3001 | high | 5.1.2 | Role grants read access to `secrets` |
| RB3002 | high | 5.1.2 | Role grants write access to `secrets` |
| RB3003 | medium | | Role grants write access to `configmaps` |
| RB3004 | high | 5.1.2 | Role can `exec` into pods (`pods/exec`) |
| RB3005 | medium | | Role can `attach` to pods (`pods/attach`) |
| RB3006 | medium | | Role can access pod logs (`pods/log`) |
| RB3007 | critical | | Role can access `etcd` directly |
| RB3008 | medium | | Role grants write access to `persistentvolumes` |
| RB3009 | high | 5.1.2 | Role accesses secrets via wildcard apiGroup |
| RB3010 | medium | | Role can use `pods/portforward` — bypasses NetworkPolicies |
| RB3011 | high | 5.1.2 | Role can access `nodes/proxy` — full kubelet API access |
| RB3012 | medium | | Role can use `pods/proxy` or `services/proxy` |

### RB4xxx — ServiceAccount Design (9 rules)

| ID | Severity | CIS | Description |
|----|----------|-----|-------------|
| RB4001 | info | 5.1.6 | `automountServiceAccountToken` not set to `false` |
| RB4002 | low | 5.1.5 | ServiceAccount name is `default` used in RoleBinding |
| RB4003 | high | 5.1.5 | ServiceAccount bound to ClusterRole with broad permissions |
| RB4004 | low | | ServiceAccount without namespace scope |
| RB4005 | info | | ServiceAccount with no associated Role/ClusterRole |
| RB4006 | low | | RoleBinding for same SA across multiple namespaces |
| RB4007 | info | | ServiceAccount without description annotation |
| RB4008 | low | | ServiceAccount token auto-mounted without expiry hint |
| RB4009 | low | 5.1.4 | ServiceAccount can create pods — potential token theft via pod spec |

### RB5xxx — Cluster-Level Risks (8 rules)

| ID | Severity | CIS | Description |
|----|----------|-----|-------------|
| RB5001 | critical | 5.1.1 | RoleBinding to `system:unauthenticated` |
| RB5002 | critical | 5.1.1 | RoleBinding to `system:anonymous` |
| RB5003 | medium | | ClusterRoleBinding count exceeds threshold |
| RB5004 | medium | | Multiple ClusterRoles with overlapping permissions |
| RB5005 | info | | Unused Role (no RoleBinding references it) |
| RB5006 | info | | Orphaned RoleBinding (references non-existent Role) |
| RB5007 | medium | | RoleBinding to `system:authenticated` (all authenticated users) |
| RB5008 | medium | | Role grants write access to `leases` — disrupts leader election |

### RB6xxx — Cross-Namespace & Network Risks (3 rules)

| ID | Severity | CIS | Description |
|----|----------|-----|-------------|
| RB6001 | medium | | RoleBinding subjects a ServiceAccount from a different namespace |
| RB6002 | critical | 5.1.7 | Binding to `system:masters` — bypasses RBAC, cannot be audited |
| RB6003 | medium | 5.3.2 | Role grants write access to `networkpolicies` — can break network isolation |

### RB7xxx — Admission & Runtime Control (2 rules)

| ID | Severity | CIS | Description |
|----|----------|-----|-------------|
| RB7001 | high | 5.1.3 | Role grants write access to admission webhook configurations |
| RB7002 | high | 5.1.3 | Role grants write access to `runtimeclasses` — bypasses container sandboxing |

### RB8xxx — Workload Risks (6 rules)

| ID | Severity | CIS | Description |
|----|----------|-----|-------------|
| RB8001 | medium | | Role grants write access to `customresourcedefinitions` |
| RB8002 | high | | Role grants write access to `daemonsets` — runs code on every node |
| RB8003 | low | | Role grants write access to `priorityclasses` — can preempt system pods |
| RB8004 | medium | | Role grants write access to `jobs` / `cronjobs` — resource abuse vector |
| RB8005 | medium | | Role grants write access to `statefulsets` — persistent workload with volume access |
| RB8006 | low | | Role grants write access to `horizontalpodautoscalers` — scale-to-zero DoS |

### RB9xxx — Node & Resource Control (4 rules)

| ID | Severity | CIS | Description |
|----|----------|-----|-------------|
| RB9001 | high | 5.1.3 | Role grants write access to `nodes/status` — allows faking node conditions |
| RB9002 | medium | | Role grants write access to `pods/status` — allows faking pod readiness |
| RB9003 | medium | | Role grants write access to `resourcequotas` — allows removing namespace limits |
| RB9004 | low | | Role grants write access to `limitranges` — allows removing container limits |

### IS1xxx — Istio AuthorizationPolicy (4 rules)

| ID | Severity | Description |
|----|----------|-------------|
| IS1001 | high | AuthorizationPolicy ALLOW with no rules (allows all traffic) |
| IS1002 | medium | Wildcard principal `*` (allows any identity) |
| IS1003 | medium | Wildcard HTTP method `*` |
| IS1004 | info | Wildcard namespace in source |

---

## Risk Scoring

Each ServiceAccount receives a 0–100 risk score based on:

- Bound role severity (wildcard verb/resource = high)
- Reachability to `cluster-admin` via privilege escalation graph
- Direct access to secrets or `exec` capability
- `automountServiceAccountToken` enabled

```
Score  0–29:   LOW      — Acceptable
Score 30–59:   MEDIUM   — Review recommended
Score 60–79:   HIGH     — Action required
Score 80–100:  CRITICAL — Immediate attention
```

Special bonuses applied to base score:
- Direct `cluster-admin` binding: +80
- Wildcard role: +30
- Escalation chain leading to `cluster-admin`: +40

## Privilege Escalation Graph

```bash
# DOT output (pipe to Graphviz)
rbacvet --map --dir ./rbac/ | dot -Tpng -o graph.png

# JSON output for programmatic use
rbacvet --map --map-format json --cluster | jq '.escalationPaths'
```

Example JSON output:
```json
{
  "escalationPaths": [
    {
      "from": "ServiceAccount/api-server",
      "chain": ["Role/deployer", "ClusterRole/admin-role", "cluster-admin"],
      "risk": "CRITICAL"
    }
  ]
}
```

## Configuration

Create `.rbacvet.yaml` in your project root:

```yaml
# Suppress specific rules
ignore:
  - RB5005   # unused roles (acceptable in GitOps setups)
  - RB4007   # SA description annotation

# Override severity for specific rules
override:
  RB3001:
    severity: critical   # escalate secret-read to critical in this repo

# Fail CI when any SA exceeds this risk score
riskScoreThreshold: 60

# ClusterRoleBindings that are pre-approved (won't trigger RB2001)
trustedClusterAdminBindings:
  - name: cluster-admin

# Webhook / Slack notification URL
notifyUrl: https://hooks.slack.com/services/XXX/YYY/ZZZ
```

### Exemption policies

Create `exemptions.yaml` for time-bound or team-scoped exemptions:

```yaml
exemptions:
  - rule: RB5005
    resource: "Role/monitoring/prometheus-reader"
    reason: "Managed externally by Helm chart"
    expires: "2026-12-31"

  - rule: RB4007
    resource: "ServiceAccount/*/fluentd"   # wildcard namespace
    reason: "Logging SA — description in Helm values"
```

```bash
rbacvet --policy ./exemptions.yaml --dir ./rbac/
```

## CI Integration

### Quick setup

```bash
rbacvet --init-ci github    # creates .github/workflows/rbacvet.yml
rbacvet --init-ci gitlab    # creates .gitlab-ci.yml
```

### Manual GitHub Actions

```yaml
- name: Scan RBAC
  run: |
    npm install -g rbacvet
    rbacvet --format sarif --dir ./rbac/ > rbac-results.sarif

- name: Upload to GitHub Security tab
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: rbac-results.sarif
```

### Exit codes

| Code | Meaning |
|------|---------|
| 0 | No violations |
| 1 | medium / low violations only |
| 2 | critical / high violations, or risk score threshold exceeded |

## Fix Suggestions

RBACVet can generate minimal YAML patches to fix violations:

```bash
# Show suggestions (does not modify files)
rbacvet --fix --dir ./rbac/

# Apply patches to source files (atomic write via .rbacvet.tmp)
rbacvet --apply-fixes --dir ./rbac/

# Preview what would change
rbacvet --apply-fixes --dry-run --dir ./rbac/

# Japanese explanations
rbacvet --fix --fix-lang ja --dir ./rbac/
```

Rules with `autoApplicable: true` are safe to apply automatically. Others require human review.

## LLM-Powered Fixes

Set `ANTHROPIC_API_KEY` to enable AI-generated fix suggestions using Claude:

```bash
export ANTHROPIC_API_KEY=sk-ant-...
rbacvet --fix --dir ./rbac/
```

Without the key, rule-based suggestions are used for 60+ rules. With the key, LLM suggestions are merged for violations not covered by rule-based logic.

## License

MIT
