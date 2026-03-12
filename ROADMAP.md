# RBACVet Roadmap

## v0.5.0 (current) — Policy & Reporting

All features complete. 521 tests, 27 test files, 74 rules.

### Completed milestones

- [x] **v0.1.0** — Manifest Mode: static YAML analysis, 44 rules, TTY/JSON/SARIF output
- [x] **v0.2.0** — Live Cluster Mode: `--cluster`, `--context`, `--namespace`, `--diff`
- [x] **v0.3.0** — Privilege Escalation Graph: `--map`, DOT/JSON output, cycle detection
- [x] **v0.4.0** — LLM Fix Suggestions: `--fix`, `--apply-fixes`, rule-based patches for 60+ rules
- [x] **v0.5.0** — Policy & Reporting: HTML report, exemption policies, scheduled scans, webhook notifications
- [x] **Post-roadmap** — Severity 5-level (critical/high/medium/low/info), CIS Benchmark IDs, Istio IS1 rules, RB6–RB9 rule categories

### Post-roadmap improvements

| Item | Status |
|------|--------|
| 5-level severity (critical/high/medium/low/info) | Done |
| CIS Kubernetes Benchmark IDs on 30+ rules | Done |
| Istio AuthorizationPolicy rules (IS1001–IS1004) | Done |
| RB6 Cross-namespace & network risks | Done |
| RB7 Admission & runtime control | Done |
| RB8 Workload risks (DaemonSet, StatefulSet, HPA, Jobs) | Done |
| RB9 Node & resource control (nodes/status, resourcequotas, limitranges) | Done |
| Fix coverage expanded to 61 rules | Done |
| `--init-ci github/gitlab` scaffolding command | Done |
| `--list-rules` and `--explain <rule>` commands | Done |
| RB4003–RB4009 ServiceAccount fixes | Done |
| RB1004–RB1014 additional least-privilege fixes | Done |

---

## v0.6.0 — Planned

Accuracy and false-positive reduction.

- [ ] `--baseline` flag: snapshot current violations, only report new ones in CI
- [ ] Namespace-scoped rule suppression in `.rbacvet.yaml`
- [ ] `--output-file` flag to write results without redirecting stdout
- [ ] `rbacvet explain` subcommand with remediation examples
- [ ] Structured logging (`--log-level debug`) for troubleshooting cluster scans

## v0.7.0 — Planned

Ecosystem integrations.

- [ ] Admission webhook mode: validate RBAC resources on `kubectl apply`
- [ ] Helm chart values scanner (detect RBAC settings in values.yaml)
- [ ] ArgoCD / Flux integration: scan before sync
- [ ] VS Code extension (inline diagnostics)
- [ ] Pre-commit hook template

## Ideas backlog

- OPA policy output format (generate Rego from violations)
- Multi-cluster comparison report
- RBAC audit log correlation (cluster events → which rules fired)
- `--watch` mode for live cluster drift detection
