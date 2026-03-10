# RBACVet

Kubernetes RBAC security analyzer. Detects over-privileged roles, privilege escalation paths, and dangerous permission bindings — with risk scoring and fix suggestions.

```
$ rbacvet --dir ./rbac/

rbac/admin-role.yaml
  RB1001  error    ClusterRole/admin-role  wildcard verbs on all resources
  RB2001  error    ClusterRoleBinding/admin-binding  binds to cluster-admin
  RB3001  warning  Role/app-role  grants read/write access to secrets

rbac/service-accounts.yaml
  RB4001  warning  ServiceAccount/api-server  automountServiceAccountToken not disabled

Risk Score: ServiceAccount/api-server → 87/100 (CRITICAL)
Privilege escalation path found: api-server → admin-role → cluster-admin

4 errors, 2 warnings across 3 resources
```

## Installation

```bash
npm install -g rbacvet
```

## Usage

```bash
# Scan RBAC manifest files
rbacvet role.yaml rolebinding.yaml serviceaccount.yaml

# Scan a directory
rbacvet --dir ./rbac/

# Live cluster scan (uses current kubeconfig)
rbacvet --cluster
rbacvet --cluster --namespace production
rbacvet --cluster --all-namespaces

# Scan from GitHub
rbacvet --github owner/repo

# Privilege escalation mapping
rbacvet --map --dir ./rbac/
rbacvet --map --cluster

# Output formats
rbacvet --format tty   --dir ./rbac/   # colored terminal (default)
rbacvet --format json  --dir ./rbac/   # JSON with risk scores
rbacvet --format sarif --dir ./rbac/   # SARIF 2.1
```

## Rules

40+ rules across 5 categories:

| Prefix | Category | Count |
|--------|----------|-------|
| RB1xxx | Least Privilege Violations | 12 |
| RB2xxx | Privilege Escalation Paths | 10 |
| RB3xxx | Secret / Data Access | 8 |
| RB4xxx | ServiceAccount Design | 8 |
| RB5xxx | Cluster-Level Risks | 6 |

### RB1xxx — Least Privilege Violations

| ID | Severity | Description |
|----|----------|-------------|
| RB1001 | error | Wildcard `*` in verbs |
| RB1002 | error | Wildcard `*` in resources |
| RB1003 | warning | Wildcard `*` in apiGroups |
| RB1004 | error | `create` + `delete` combined on same resource |
| RB1005 | warning | `update` + `patch` combined with no resource restriction |
| RB1006 | error | ClusterRole with write access to all core resources |
| RB1007 | warning | Role grants `list` on all resources |
| RB1008 | warning | Role grants `watch` on all resources |
| RB1009 | error | Role with `*` verbs on `nodes` resource |
| RB1010 | error | Role with `*` verbs on `namespaces` resource |
| RB1011 | warning | Role with `deletecollection` verb |
| RB1012 | info | Role with more than 20 permission rules |

### RB2xxx — Privilege Escalation Paths

| ID | Severity | Description |
|----|----------|-------------|
| RB2001 | error | ClusterRoleBinding binds to `cluster-admin` |
| RB2002 | error | Role with `escalate` verb |
| RB2003 | error | Role with `bind` verb |
| RB2004 | error | Role can modify Role/ClusterRole (RBAC management) |
| RB2005 | error | Role can modify RoleBinding/ClusterRoleBinding |
| RB2006 | error | Impersonation permissions (users, groups, serviceaccounts) |
| RB2007 | error | Role grants access to `tokenreviews` or `subjectaccessreviews` |
| RB2008 | warning | Role can create/update `ValidatingWebhookConfiguration` |
| RB2009 | warning | Role can create/update `MutatingWebhookConfiguration` |
| RB2010 | error | Detected privilege escalation chain (A → B → cluster-admin) |

### RB3xxx — Secret & Data Access

| ID | Severity | Description |
|----|----------|-------------|
| RB3001 | warning | Role grants read access to `secrets` |
| RB3002 | error | Role grants write access to `secrets` |
| RB3003 | warning | Role grants access to `configmaps` with write |
| RB3004 | error | Role can `exec` into pods (`pods/exec`) |
| RB3005 | warning | Role can `attach` to pods (`pods/attach`) |
| RB3006 | warning | Role can access pod logs (`pods/log`) |
| RB3007 | error | Role can access `etcd` directly |
| RB3008 | warning | Role grants access to `persistentvolumes` |

### RB4xxx — ServiceAccount Design

| ID | Severity | Description |
|----|----------|-------------|
| RB4001 | warning | `automountServiceAccountToken` not set to `false` |
| RB4002 | warning | ServiceAccount name is `default` used in RoleBinding |
| RB4003 | error | ServiceAccount bound to ClusterRole with broad permissions |
| RB4004 | warning | ServiceAccount without namespace scope |
| RB4005 | info | ServiceAccount with no associated Role/ClusterRole |
| RB4006 | warning | RoleBinding in multiple namespaces for same SA |
| RB4007 | info | ServiceAccount without description annotation |
| RB4008 | warning | ServiceAccount token projected without expiry |

### RB5xxx — Cluster-Level Risks

| ID | Severity | Description |
|----|----------|-------------|
| RB5001 | error | RoleBinding to `system:unauthenticated` |
| RB5002 | error | RoleBinding to `system:anonymous` |
| RB5003 | warning | ClusterRoleBinding count exceeds threshold |
| RB5004 | warning | Multiple ClusterRoles with overlapping permissions |
| RB5005 | info | Unused Role (no RoleBinding references it) |
| RB5006 | info | Orphaned RoleBinding (references non-existent Role) |

## Risk Scoring

Each ServiceAccount receives a 0–100 risk score based on:

- Bound role severity (wildcard = high)
- Privilege escalation reachability to `cluster-admin`
- Direct access to secrets or exec capability
- `automountServiceAccountToken` enabled

```
Score 0–29:   LOW      ✅ Acceptable
Score 30–59:  MEDIUM   ⚠️  Review recommended
Score 60–79:  HIGH     🔴 Action required
Score 80–100: CRITICAL 🚨 Immediate attention
```

## Privilege Escalation Map

```bash
rbacvet --map --format json --cluster | jq '.escalationPaths'
```

Output example:
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

Create `.rbacvet.yaml`:

```yaml
ignore:
  - RB5005   # Unused roles (ok in some setups)
  - RB4007   # SA description annotation

override:
  RB3001:
    severity: error  # escalate secret-read to error

# Risk score threshold for CI failure
riskScoreThreshold: 60

# Trusted ClusterRoleBindings (won't flag RB2001)
trustedClusterAdminBindings:
  - name: system:masters
```

## CI Integration

```yaml
- name: Scan RBAC
  run: |
    npm install -g rbacvet
    rbacvet --format sarif --dir ./rbac/ > rbac-results.sarif

- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: rbac-results.sarif
```

## License

MIT
