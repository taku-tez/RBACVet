# RBACVet Roadmap

## v0.1.0 — Manifest Mode (Week 3)

**Goal:** Static analysis of RBAC YAML files with risk scoring.

- [ ] YAML parser (reuse ManifestVet parser)
- [ ] Rule engine (RB1–5, 40+ rules)
- [ ] Risk scoring engine (0–100 per ServiceAccount)
- [ ] TTY / JSON / SARIF formatters
- [ ] CLI (`--dir`, `--format`, `--ignore`, `--severity`)
- [ ] 120+ tests
- [ ] npm publish

---

## v0.2.0 — Live Cluster Mode (Week 4)

**Goal:** Analyze RBAC directly from a running cluster.

- [ ] `--cluster` flag — use current kubeconfig
- [ ] `--context <name>` — kubeconfig context targeting
- [ ] `--namespace` / `--all-namespaces`
- [ ] Fetch Role, ClusterRole, RoleBinding, ClusterRoleBinding, ServiceAccount via K8s API
- [ ] Cross-namespace binding detection
- [ ] `rbacvet --diff` — compare cluster vs local manifests

---

## v0.3.0 — Privilege Escalation Graph (Week 5)

**Goal:** Visualize and detect privilege escalation paths.

- [ ] Graph builder: ServiceAccount → Role → effective permissions
- [ ] Reachability analysis: can SA X reach cluster-admin?
- [ ] `--map` flag — output full escalation graph
- [ ] DOT format output (Graphviz visualization)
- [ ] JSON path output for programmatic consumption
- [ ] Cycle detection in RoleBinding chains

---

## v0.4.0 — LLM Fix Suggestions (Week 6–7)

**Goal:** Generate least-privilege Role replacement suggestions.

- [ ] `--fix` flag — suggest minimal Role with only required permissions
- [ ] `--fix-lang ja` — Japanese explanations
- [ ] LLM-powered Role refactoring (given workload, suggest minimal RBAC)
- [ ] Automated RBAC tightening with `--apply-fixes`

---

## v0.5.0 — Policy & Reporting (Week 8)

**Goal:** Enterprise-grade policy enforcement and reporting.

- [ ] `--format html` — interactive HTML report
- [ ] Per-team RBAC policy files
- [ ] Exemption management with audit trail
- [ ] Periodic cluster scan scheduling
- [ ] Slack / webhook notifications for new violations

---

## Future

- [ ] OPA/Rego custom policy integration
- [ ] RBAC comparison across environments (dev vs prod)
- [ ] Service mesh (Istio) authorization policy analysis
- [ ] CIS Kubernetes Benchmark mapping
