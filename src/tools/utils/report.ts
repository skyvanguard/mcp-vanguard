import { z } from 'zod';
import { getScope } from '../../config.js';

export const generateReportSchema = z.object({
  title: z.string().describe('Report title'),
  target: z.string().describe('Primary target of the engagement'),
  findings: z.array(z.object({
    title: z.string(),
    severity: z.enum(['critical', 'high', 'medium', 'low', 'info']),
    description: z.string(),
    evidence: z.string().optional(),
    remediation: z.string().optional(),
    references: z.array(z.string()).optional()
  })).describe('List of findings'),
  methodology: z.array(z.string()).optional().describe('Steps taken during assessment'),
  toolsUsed: z.array(z.string()).optional().describe('Tools used'),
  timeframe: z.object({
    start: z.string(),
    end: z.string()
  }).optional().describe('Assessment timeframe')
});

export type GenerateReportInput = z.infer<typeof generateReportSchema>;

interface Finding {
  title: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  description: string;
  evidence?: string;
  remediation?: string;
  references?: string[];
}

export function generateReport(input: GenerateReportInput): {
  success: boolean;
  markdown: string;
  summary: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
    total: number;
  };
} {
  const { title, target, findings, methodology, toolsUsed, timeframe } = input;
  const scope = getScope();

  const summary = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0,
    total: findings.length
  };

  for (const finding of findings) {
    summary[finding.severity]++;
  }

  const sortedFindings = [...findings].sort((a, b) => {
    const order = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
    return order[a.severity] - order[b.severity];
  });

  const lines: string[] = [
    `# ${title}`,
    '',
    '## Executive Summary',
    '',
    `This security assessment was conducted against **${target}**.`,
    '',
    '### Findings Summary',
    '',
    '| Severity | Count |',
    '|----------|-------|',
    `| 🔴 Critical | ${summary.critical} |`,
    `| 🟠 High | ${summary.high} |`,
    `| 🟡 Medium | ${summary.medium} |`,
    `| 🔵 Low | ${summary.low} |`,
    `| ⚪ Info | ${summary.info} |`,
    `| **Total** | **${summary.total}** |`,
    ''
  ];

  if (timeframe) {
    lines.push('### Assessment Period');
    lines.push('');
    lines.push(`- **Start**: ${timeframe.start}`);
    lines.push(`- **End**: ${timeframe.end}`);
    lines.push('');
  }

  if (scope.length > 0) {
    lines.push('### Scope');
    lines.push('');
    lines.push('The following targets were in scope:');
    lines.push('');
    for (const s of scope) {
      lines.push(`- \`${s}\``);
    }
    lines.push('');
  }

  if (methodology && methodology.length > 0) {
    lines.push('## Methodology');
    lines.push('');
    for (let i = 0; i < methodology.length; i++) {
      lines.push(`${i + 1}. ${methodology[i]}`);
    }
    lines.push('');
  }

  if (toolsUsed && toolsUsed.length > 0) {
    lines.push('## Tools Used');
    lines.push('');
    for (const tool of toolsUsed) {
      lines.push(`- ${tool}`);
    }
    lines.push('');
  }

  lines.push('## Detailed Findings');
  lines.push('');

  for (let i = 0; i < sortedFindings.length; i++) {
    const finding = sortedFindings[i];
    const severityEmoji = getSeverityEmoji(finding.severity);

    lines.push(`### ${i + 1}. ${severityEmoji} ${finding.title}`);
    lines.push('');
    lines.push(`**Severity**: ${finding.severity.toUpperCase()}`);
    lines.push('');
    lines.push('#### Description');
    lines.push('');
    lines.push(finding.description);
    lines.push('');

    if (finding.evidence) {
      lines.push('#### Evidence');
      lines.push('');
      lines.push('```');
      lines.push(finding.evidence);
      lines.push('```');
      lines.push('');
    }

    if (finding.remediation) {
      lines.push('#### Remediation');
      lines.push('');
      lines.push(finding.remediation);
      lines.push('');
    }

    if (finding.references && finding.references.length > 0) {
      lines.push('#### References');
      lines.push('');
      for (const ref of finding.references) {
        lines.push(`- ${ref}`);
      }
      lines.push('');
    }

    lines.push('---');
    lines.push('');
  }

  lines.push('## Appendix');
  lines.push('');
  lines.push('### Risk Rating Definitions');
  lines.push('');
  lines.push('| Severity | Description |');
  lines.push('|----------|-------------|');
  lines.push('| Critical | Immediate exploitation possible with severe business impact |');
  lines.push('| High | Exploitation likely with significant business impact |');
  lines.push('| Medium | Exploitation possible with moderate business impact |');
  lines.push('| Low | Exploitation unlikely or limited business impact |');
  lines.push('| Info | Informational finding with no direct security impact |');
  lines.push('');

  lines.push('---');
  lines.push('');
  lines.push(`*Report generated by mcp-vanguard on ${new Date().toISOString()}*`);

  return {
    success: true,
    markdown: lines.join('\n'),
    summary
  };
}

function getSeverityEmoji(severity: string): string {
  const emojis: Record<string, string> = {
    critical: '🔴',
    high: '🟠',
    medium: '🟡',
    low: '🔵',
    info: '⚪'
  };
  return emojis[severity] || '⚪';
}

export function generateFindingTemplate(
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info'
): Finding {
  return {
    title: '',
    severity,
    description: '',
    evidence: '',
    remediation: '',
    references: []
  };
}

export function calculateRiskScore(findings: Finding[]): {
  score: number;
  rating: string;
  breakdown: Record<string, number>;
} {
  const weights = {
    critical: 10,
    high: 7,
    medium: 4,
    low: 1,
    info: 0
  };

  let totalScore = 0;
  const breakdown: Record<string, number> = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0
  };

  for (const finding of findings) {
    totalScore += weights[finding.severity];
    breakdown[finding.severity]++;
  }

  let rating: string;
  if (totalScore >= 50) {
    rating = 'Critical';
  } else if (totalScore >= 30) {
    rating = 'High';
  } else if (totalScore >= 15) {
    rating = 'Medium';
  } else if (totalScore >= 5) {
    rating = 'Low';
  } else {
    rating = 'Minimal';
  }

  return {
    score: totalScore,
    rating,
    breakdown
  };
}
