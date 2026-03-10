import type { Violation, Rule } from '../rules/types';
import type { ServiceAccountScore } from '../engine/scorer';
import type { FilterResult, ResolvedExemption } from '../policy/types';

export interface HTMLReportOptions {
  title?: string;
  generatedAt?: Date;
  filesScanned?: number;
  filterResult?: FilterResult;
  dotSource?: string;
  ruleMap?: Map<string, Rule>;
}

const SEVERITY_COLOR: Record<string, string> = {
  error: '#dc2626',
  warning: '#d97706',
  info: '#2563eb',
};

const LEVEL_COLOR: Record<string, string> = {
  CRITICAL: '#dc2626',
  HIGH: '#ea580c',
  MEDIUM: '#d97706',
  LOW: '#16a34a',
};

function escapeHtml(s: string): string {
  return s
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function badge(text: string, color: string): string {
  return `<span style="background:${color};color:#fff;padding:2px 8px;border-radius:12px;font-size:11px;font-weight:bold">${escapeHtml(text)}</span>`;
}

function scoreBar(score: number, level: string): string {
  const color = LEVEL_COLOR[level] ?? '#888';
  return `<div style="display:flex;align-items:center;gap:8px">
    <div style="flex:1;background:#e5e7eb;border-radius:4px;height:16px;overflow:hidden">
      <div style="width:${score}%;background:${color};height:100%;transition:width 0.3s"></div>
    </div>
    <span style="font-size:12px;font-weight:bold;color:${color};min-width:40px">${score}/100</span>
    ${badge(level, color)}
  </div>`;
}

function violationTable(violations: Violation[], ruleMap?: Map<string, Rule>): string {
  if (violations.length === 0) {
    return '<p style="color:#16a34a;font-weight:bold">✅ No violations found</p>';
  }
  const rows = violations.map(v => {
    const color = SEVERITY_COLOR[v.severity] ?? '#888';
    const cisId = ruleMap?.get(v.rule)?.cisId;
    const cisBadge = cisId
      ? ` <span style="background:#1e40af;color:#fff;padding:1px 6px;border-radius:10px;font-size:10px;font-weight:bold;margin-left:4px">${escapeHtml(cisId)}</span>`
      : '';
    return `<tr>
      <td>${badge(v.severity, color)}</td>
      <td><code>${escapeHtml(v.rule)}</code>${cisBadge}</td>
      <td style="font-size:12px">${escapeHtml(v.resource)}</td>
      <td style="color:#6b7280;font-size:12px">${escapeHtml(v.file)}:${v.line}</td>
      <td style="font-size:13px">${escapeHtml(v.message)}</td>
    </tr>`;
  }).join('\n');

  return `<table style="width:100%;border-collapse:collapse;font-family:system-ui,sans-serif">
    <thead>
      <tr style="background:#f3f4f6;text-align:left">
        <th style="padding:8px 12px">Severity</th>
        <th style="padding:8px 12px">Rule</th>
        <th style="padding:8px 12px">Resource</th>
        <th style="padding:8px 12px">Location</th>
        <th style="padding:8px 12px">Message</th>
      </tr>
    </thead>
    <tbody>
      ${rows}
    </tbody>
  </table>`;
}

function exemptedTable(exempted: FilterResult['exempted']): string {
  if (exempted.length === 0) return '';
  const rows = exempted.map(({ violation, exemption }) => {
    const color = SEVERITY_COLOR[violation.severity] ?? '#888';
    return `<tr>
      <td>${badge(violation.severity, color)}</td>
      <td><code>${escapeHtml(violation.rule)}</code></td>
      <td style="font-size:12px">${escapeHtml(violation.resource)}</td>
      <td style="font-size:12px;color:#6b7280">${escapeHtml(exemption.reason)}</td>
      <td style="font-size:12px;color:#6b7280">${escapeHtml(exemption.author)}</td>
      <td style="font-size:12px">${exemption.expires ? escapeHtml(exemption.expires) : '—'}</td>
    </tr>`;
  }).join('\n');
  return `<section style="margin-bottom:32px">
    <h2 style="font-size:18px;color:#374151">Exempted Violations (${exempted.length})</h2>
    <table style="width:100%;border-collapse:collapse">
      <thead>
        <tr style="background:#fef9c3;text-align:left">
          <th style="padding:8px 12px">Severity</th>
          <th style="padding:8px 12px">Rule</th>
          <th style="padding:8px 12px">Resource</th>
          <th style="padding:8px 12px">Reason</th>
          <th style="padding:8px 12px">Author</th>
          <th style="padding:8px 12px">Expires</th>
        </tr>
      </thead>
      <tbody>${rows}</tbody>
    </table>
  </section>`;
}

export function formatHTML(
  violations: Violation[],
  scores: ServiceAccountScore[],
  opts: HTMLReportOptions = {},
): string {
  const now = opts.generatedAt ?? new Date();
  const title = opts.title ?? 'RBACVet Security Report';
  const errors = violations.filter(v => v.severity === 'error').length;
  const warnings = violations.filter(v => v.severity === 'warning').length;
  const infos = violations.filter(v => v.severity === 'info').length;
  const exempted = opts.filterResult?.exempted.length ?? 0;

  const scoreRows = scores.filter(s => s.score > 0).map(s =>
    `<div style="margin-bottom:12px">
      <div style="font-size:13px;font-weight:bold;margin-bottom:4px">${escapeHtml(s.name)}</div>
      ${scoreBar(s.score, s.level)}
      ${s.escalationPath ? `<div style="font-size:11px;color:#dc2626;margin-top:4px">⚠ Escalation: ${escapeHtml(s.escalationPath.join(' → '))}</div>` : ''}
    </div>`
  ).join('\n');

  const summaryColor = errors > 0 ? '#dc2626' : warnings > 0 ? '#d97706' : '#16a34a';

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>${escapeHtml(title)}</title>
  <style>
    * { box-sizing: border-box; }
    body { font-family: system-ui, -apple-system, sans-serif; margin: 0; padding: 0; background: #f9fafb; color: #111827; }
    .container { max-width: 1200px; margin: 0 auto; padding: 24px; }
    header { background: #1e293b; color: white; padding: 24px; margin-bottom: 24px; }
    header h1 { margin: 0 0 8px; font-size: 24px; }
    header p { margin: 0; color: #94a3b8; font-size: 14px; }
    section { background: white; border-radius: 8px; padding: 24px; margin-bottom: 24px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }
    h2 { font-size: 18px; color: #374151; margin-top: 0; }
    .stats { display: flex; gap: 16px; flex-wrap: wrap; margin-bottom: 24px; }
    .stat-card { background: white; border-radius: 8px; padding: 16px 24px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); min-width: 120px; text-align: center; }
    .stat-number { font-size: 32px; font-weight: bold; }
    .stat-label { font-size: 12px; color: #6b7280; text-transform: uppercase; letter-spacing: 0.05em; }
    table tbody tr:nth-child(even) { background: #f9fafb; }
    table td, table th { padding: 8px 12px; border-bottom: 1px solid #e5e7eb; vertical-align: middle; }
    code { background: #f3f4f6; padding: 1px 6px; border-radius: 4px; font-size: 12px; font-family: monospace; }
    details summary { cursor: pointer; padding: 8px 0; font-weight: bold; }
    pre { background: #1e293b; color: #e2e8f0; padding: 16px; border-radius: 6px; overflow: auto; font-size: 12px; max-height: 400px; }
    footer { text-align: center; color: #9ca3af; font-size: 12px; padding: 16px; }
    @media (max-width: 768px) { .stats { flex-direction: column; } }
  </style>
</head>
<body>
  <header>
    <div class="container">
      <h1>🔐 ${escapeHtml(title)}</h1>
      <p>Generated: ${now.toISOString()} | Files scanned: ${opts.filesScanned ?? 0}</p>
    </div>
  </header>

  <div class="container">
    <div class="stats">
      <div class="stat-card">
        <div class="stat-number" style="color:${summaryColor}">${errors}</div>
        <div class="stat-label">Errors</div>
      </div>
      <div class="stat-card">
        <div class="stat-number" style="color:#d97706">${warnings}</div>
        <div class="stat-label">Warnings</div>
      </div>
      <div class="stat-card">
        <div class="stat-number" style="color:#2563eb">${infos}</div>
        <div class="stat-label">Info</div>
      </div>
      ${exempted > 0 ? `<div class="stat-card">
        <div class="stat-number" style="color:#6b7280">${exempted}</div>
        <div class="stat-label">Exempted</div>
      </div>` : ''}
    </div>

    ${scoreRows ? `<section>
      <h2>Risk Scores by ServiceAccount</h2>
      ${scoreRows}
    </section>` : ''}

    <section>
      <h2>Violations (${violations.length})</h2>
      ${violationTable(violations, opts.ruleMap)}
    </section>

    ${opts.filterResult && opts.filterResult.exempted.length > 0 ? exemptedTable(opts.filterResult.exempted) : ''}

    ${opts.dotSource ? `<section>
      <h2>Privilege Escalation Graph</h2>
      <details>
        <summary>Show DOT source (paste into Graphviz or https://dreampuf.github.io/GraphvizOnline/)</summary>
        <pre>${escapeHtml(opts.dotSource)}</pre>
      </details>
    </section>` : ''}

    <footer>
      Generated by <strong>rbacvet</strong> v0.5.0 | <a href="https://github.com/RBACVet/rbacvet" style="color:#6b7280">github.com/RBACVet/rbacvet</a>
    </footer>
  </div>
</body>
</html>`;
}
