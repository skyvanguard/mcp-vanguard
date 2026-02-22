import { z } from 'zod';

export const vulnCorrelateSchema = z.object({
  findings: z.array(z.object({
    tool: z.string(),
    type: z.string(),
    severity: z.enum(['info', 'low', 'medium', 'high', 'critical']),
    target: z.string(),
    details: z.string(),
  })).describe('Array of findings from different tools to correlate'),
});

export type VulnCorrelateInput = z.infer<typeof vulnCorrelateSchema>;

interface CorrelationGroup {
  title: string;
  findings: Array<{ tool: string; type: string; details: string }>;
  combinedSeverity: string;
  attackChain?: string;
}

export async function vulnCorrelate(input: VulnCorrelateInput): Promise<{
  success: boolean;
  totalFindings: number;
  correlations: CorrelationGroup[];
  attackChains: string[];
  summary: { critical: number; high: number; medium: number; low: number; info: number };
}> {
  const { findings } = input;

  const summary = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of findings) {
    summary[f.severity]++;
  }

  // Group findings by target
  const byTarget = new Map<string, typeof findings>();
  for (const f of findings) {
    const existing = byTarget.get(f.target) || [];
    existing.push(f);
    byTarget.set(f.target, existing);
  }

  const correlations: CorrelationGroup[] = [];
  const attackChains: string[] = [];

  for (const [target, targetFindings] of byTarget) {
    if (targetFindings.length < 2) continue;

    const types = targetFindings.map(f => f.type.toLowerCase());
    const maxSeverity = getMaxSeverity(targetFindings.map(f => f.severity));

    // Detect common attack chains
    if (types.some(t => t.includes('sqli')) && types.some(t => t.includes('lfi'))) {
      attackChains.push(`${target}: SQLi + LFI → Potential RCE via SQL file read + code execution`);
    }
    if (types.some(t => t.includes('xss')) && types.some(t => t.includes('open-redirect'))) {
      attackChains.push(`${target}: XSS + Open Redirect → Credential phishing via reflected XSS with redirect`);
    }
    if (types.some(t => t.includes('ssrf')) && types.some(t => t.includes('metadata'))) {
      attackChains.push(`${target}: SSRF + Cloud Metadata → AWS/GCP credential theft via SSRF to IMDSv1`);
    }
    if (types.some(t => t.includes('deserialization')) && types.some(t => t.includes('command'))) {
      attackChains.push(`${target}: Deserialization + Command Injection → RCE via gadget chain`);
    }

    correlations.push({
      title: `${target} (${targetFindings.length} findings)`,
      findings: targetFindings.map(f => ({ tool: f.tool, type: f.type, details: f.details })),
      combinedSeverity: maxSeverity,
    });
  }

  return {
    success: true,
    totalFindings: findings.length,
    correlations,
    attackChains,
    summary,
  };
}

function getMaxSeverity(severities: string[]): string {
  const order = ['critical', 'high', 'medium', 'low', 'info'];
  for (const s of order) {
    if (severities.includes(s)) return s;
  }
  return 'info';
}
