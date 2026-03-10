# RBACVet Roadmap

## v0.1.0 — Manifest Mode (Week 3)

**Goal:** Static analysis of RBAC YAML files with risk scoring.

- [x] YAML parser (reuse ManifestVet parser)
- [x] Rule engine (RB1–5, 44 rules)
- [x] Risk scoring engine (0–100 per ServiceAccount)
- [x] TTY / JSON / SARIF formatters
- [x] CLI (`--dir`, `--format`, `--ignore`, `--severity`)
- [x] 131 tests
- [ ] npm publish

---

## v0.2.0 — Live Cluster Mode (Week 4)

**Goal:** Analyze RBAC directly from a running cluster.

- [x] `--cluster` flag — use current kubeconfig
- [x] `--context <name>` — kubeconfig context targeting
- [x] `--namespace` / `--all-namespaces`
- [x] Fetch Role, ClusterRole, RoleBinding, ClusterRoleBinding, ServiceAccount via K8s API
- [x] Cross-namespace binding detection (RB6001)
- [x] `rbacvet --diff` — compare cluster vs local manifests

---

## v0.3.0 — Privilege Escalation Graph (Week 5)

**Goal:** Visualize and detect privilege escalation paths.

- [x] Graph builder: ServiceAccount → Role → effective permissions
- [x] Reachability analysis: can SA X reach cluster-admin?
- [x] `--map` flag — output full escalation graph
- [x] DOT format output (Graphviz visualization)
- [x] JSON path output for programmatic consumption
- [x] Cycle detection in RoleBinding chains

---

## v0.4.0 — LLM Fix Suggestions (Week 6–7)

**Goal:** Generate least-privilege Role replacement suggestions.

- [x] `--fix` flag — suggest minimal Role with only required permissions
- [x] `--fix-lang ja` — Japanese explanations
- [x] LLM-powered Role refactoring (given workload, suggest minimal RBAC)
- [x] Automated RBAC tightening with `--apply-fixes`

---

## v0.5.0 — Policy & Reporting (Week 8)

**Goal:** Enterprise-grade policy enforcement and reporting.

- [x] `--format html` — interactive HTML report
- [x] Per-team RBAC policy files
- [x] Exemption management with audit trail
- [x] Periodic cluster scan scheduling
- [x] Slack / webhook notifications for new violations

---

## Future

- [x] OPA/Rego custom policy integration
- [x] RBAC comparison across environments (dev vs prod)
- [x] Service mesh (Istio) authorization policy analysis
- [x] CIS Kubernetes Benchmark mapping
