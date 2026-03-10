import type { Violation, ResourceGraph } from '../rules/types';
import type { ServiceAccountScore, RiskLevel } from '../engine/scorer';
import type { FilterResult } from '../policy/types';

export interface WebhookPayload {
  source: 'rbacvet';
  version: string;
  timestamp: string;
  summary: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
    exempted: number;
    maxRiskScore: number;
    maxRiskLevel: RiskLevel;
    filesScanned: number;
  };
  topViolations: Array<{
    rule: string;
    severity: string;
    resource: string;
    message: string;
    file: string;
    line: number;
  }>;
  topRiskyAccounts: Array<{
    name: string;
    score: number;
    level: RiskLevel;
    escalationPath?: string[];
  }>;
}

function toSlackBlocks(payload: WebhookPayload): object {
  const { summary } = payload;
  const level = summary.maxRiskLevel;
  const levelEmoji: Record<RiskLevel, string> = {
    CRITICAL: '🚨', HIGH: '🔴', MEDIUM: '⚠️', LOW: '✅',
  };
  const emoji = levelEmoji[level] ?? '⚠️';

  const violationText = payload.topViolations
    .slice(0, 5)
    .map(v => `• [${v.rule}] ${v.resource}: ${v.message}`)
    .join('\n');

  return {
    blocks: [
      {
        type: 'header',
        text: { type: 'plain_text', text: `${emoji} RBACVet Scan Results` },
      },
      {
        type: 'section',
        text: {
          type: 'mrkdwn',
          text: `*${summary.critical} critical*, ${summary.high} high, ${summary.medium} medium, ${summary.low} low\nMax risk: *${summary.maxRiskScore}/100* (${summary.maxRiskLevel})${summary.exempted > 0 ? `\n${summary.exempted} exempted` : ''}`,
        },
      },
      ...(violationText ? [{
        type: 'section',
        text: { type: 'mrkdwn', text: `*Top violations:*\n${violationText}` },
      }] : []),
    ],
  };
}

export async function sendWebhook(url: string, payload: WebhookPayload): Promise<void> {
  const isSlack = url.includes('hooks.slack.com');
  const body = isSlack ? toSlackBlocks(payload) : payload;

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 5000);

  try {
    const response = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
      signal: controller.signal,
    });
    if (!response.ok) {
      throw new Error(`Webhook returned HTTP ${response.status}`);
    }
  } finally {
    clearTimeout(timeout);
  }
}

export function buildWebhookPayload(
  violations: Violation[],
  scores: ServiceAccountScore[],
  filterResult: FilterResult,
  filesScanned: number,
  version = '0.5.0',
): WebhookPayload {
  const critical = violations.filter(v => v.severity === 'critical').length;
  const high = violations.filter(v => v.severity === 'high').length;
  const medium = violations.filter(v => v.severity === 'medium').length;
  const low = violations.filter(v => v.severity === 'low').length;
  const info = violations.filter(v => v.severity === 'info').length;
  const maxScore = scores.length > 0 ? scores[0].score : 0;
  const maxLevel: RiskLevel = maxScore >= 80 ? 'CRITICAL' : maxScore >= 60 ? 'HIGH' : maxScore >= 30 ? 'MEDIUM' : 'LOW';

  const topViolations = violations
    .sort((a, b) => {
      const order = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
      return (order[b.severity] ?? 0) - (order[a.severity] ?? 0);
    })
    .slice(0, 5)
    .map(v => ({ rule: v.rule, severity: v.severity, resource: v.resource, message: v.message, file: v.file, line: v.line }));

  const topRiskyAccounts = scores.slice(0, 3).map(s => ({
    name: s.name,
    score: s.score,
    level: s.level,
    escalationPath: s.escalationPath,
  }));

  return {
    source: 'rbacvet',
    version,
    timestamp: new Date().toISOString(),
    summary: {
      critical,
      high,
      medium,
      low,
      info,
      exempted: filterResult.exempted.length,
      maxRiskScore: maxScore,
      maxRiskLevel: maxLevel,
      filesScanned,
    },
    topViolations,
    topRiskyAccounts,
  };
}
