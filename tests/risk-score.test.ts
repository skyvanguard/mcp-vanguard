import { describe, it, expect } from 'vitest';
import { riskScore } from '../src/tools/analysis/risk-score.js';

describe('riskScore', () => {
  it('should score critical findings highest', async () => {
    const result = await riskScore({
      findings: [
        { type: 'SQLi', severity: 'critical', confidence: 'high', exploitable: true },
        { type: 'Info Disclosure', severity: 'info', confidence: 'low', exploitable: false },
      ],
      context: { isPublic: true, hasAuth: true, hasSensitiveData: true, isProduction: true },
    });
    expect(result.success).toBe(true);
    expect(result.scoredFindings.length).toBe(2);
    expect(result.scoredFindings[0].adjustedScore).toBeGreaterThan(result.scoredFindings[1].adjustedScore);
  });

  it('should apply context multipliers', async () => {
    const base = { type: 'XSS', severity: 'medium' as const, confidence: 'medium' as const, exploitable: false };
    const publicResult = await riskScore({
      findings: [base],
      context: { isPublic: true, hasAuth: false, hasSensitiveData: false, isProduction: false },
    });
    const privateResult = await riskScore({
      findings: [base],
      context: { isPublic: false, hasAuth: false, hasSensitiveData: false, isProduction: false },
    });
    expect(publicResult.scoredFindings[0].adjustedScore).toBeGreaterThanOrEqual(privateResult.scoredFindings[0].adjustedScore);
  });

  it('should calculate overall risk level', async () => {
    const result = await riskScore({
      findings: [{ type: 'SQLi', severity: 'critical', confidence: 'high', exploitable: true }],
      context: { isPublic: true, hasAuth: true, hasSensitiveData: true, isProduction: true },
    });
    expect(result.riskLevel).toBeDefined();
    expect(['minimal', 'low', 'medium', 'high', 'critical']).toContain(result.riskLevel);
  });

  it('should handle empty findings', async () => {
    const result = await riskScore({
      findings: [],
      context: { isPublic: false, hasAuth: false, hasSensitiveData: false, isProduction: false },
    });
    expect(result.success).toBe(true);
    expect(result.scoredFindings.length).toBe(0);
  });
});
