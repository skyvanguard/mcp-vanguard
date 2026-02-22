import { z } from 'zod';

export const riskScoreSchema = z.object({
  findings: z.array(z.object({
    type: z.string(),
    severity: z.enum(['info', 'low', 'medium', 'high', 'critical']),
    confidence: z.enum(['low', 'medium', 'high']).default('medium'),
    exploitable: z.boolean().default(false),
  })).describe('Security findings to score'),
  context: z.object({
    isPublic: z.boolean().default(true).describe('Is the target internet-facing?'),
    hasAuth: z.boolean().default(true).describe('Does the target require authentication?'),
    hasSensitiveData: z.boolean().default(false).describe('Does the target handle sensitive data?'),
    isProduction: z.boolean().default(true).describe('Is this a production environment?'),
  }).default({}),
});

export type RiskScoreInput = z.infer<typeof riskScoreSchema>;

interface ScoredFinding {
  type: string;
  baseSeverity: string;
  adjustedScore: number;
  factors: string[];
}

const SEVERITY_BASE: Record<string, number> = {
  critical: 10, high: 8, medium: 5, low: 3, info: 1,
};

const CONFIDENCE_MULTIPLIER: Record<string, number> = {
  high: 1.0, medium: 0.8, low: 0.5,
};

export async function riskScore(input: RiskScoreInput): Promise<{
  success: boolean;
  overallScore: number;
  riskLevel: 'critical' | 'high' | 'medium' | 'low' | 'minimal';
  scoredFindings: ScoredFinding[];
  contextFactors: string[];
  recommendation: string;
}> {
  const { findings, context } = input;
  const contextFactors: string[] = [];
  let contextMultiplier = 1.0;

  if (context.isPublic) { contextMultiplier *= 1.3; contextFactors.push('Internet-facing (+30%)'); }
  if (!context.hasAuth) { contextMultiplier *= 1.5; contextFactors.push('No authentication (+50%)'); }
  if (context.hasSensitiveData) { contextMultiplier *= 1.4; contextFactors.push('Sensitive data (+40%)'); }
  if (context.isProduction) { contextMultiplier *= 1.2; contextFactors.push('Production environment (+20%)'); }

  const scoredFindings: ScoredFinding[] = [];
  let totalScore = 0;

  for (const f of findings) {
    let score = SEVERITY_BASE[f.severity] || 1;
    const factors: string[] = [`Base: ${score}`];

    score *= CONFIDENCE_MULTIPLIER[f.confidence] || 0.8;
    factors.push(`Confidence ${f.confidence}: ×${CONFIDENCE_MULTIPLIER[f.confidence]}`);

    if (f.exploitable) {
      score *= 1.5;
      factors.push('Exploitable: ×1.5');
    }

    score *= contextMultiplier;
    factors.push(`Context: ×${contextMultiplier.toFixed(1)}`);

    const adjusted = Math.round(score * 10) / 10;
    scoredFindings.push({
      type: f.type,
      baseSeverity: f.severity,
      adjustedScore: adjusted,
      factors,
    });
    totalScore += adjusted;
  }

  // Normalize to 0-100 scale
  const maxPossible = findings.length * 10 * 1.5 * contextMultiplier;
  const overallScore = maxPossible > 0 ? Math.min(100, Math.round((totalScore / maxPossible) * 100)) : 0;

  const riskLevel = overallScore >= 80 ? 'critical'
    : overallScore >= 60 ? 'high'
    : overallScore >= 40 ? 'medium'
    : overallScore >= 20 ? 'low'
    : 'minimal';

  const recommendation = riskLevel === 'critical'
    ? 'Immediate remediation required. Multiple high-impact vulnerabilities detected.'
    : riskLevel === 'high'
    ? 'Prioritize remediation. Significant security issues present.'
    : riskLevel === 'medium'
    ? 'Plan remediation in next sprint. Moderate risk exposure.'
    : riskLevel === 'low'
    ? 'Address during regular maintenance. Low overall risk.'
    : 'No significant issues. Continue monitoring.';

  return {
    success: true,
    overallScore,
    riskLevel,
    scoredFindings,
    contextFactors,
    recommendation,
  };
}
