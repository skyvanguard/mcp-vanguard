import { describe, it, expect } from 'vitest';
import { diffReport } from '../src/tools/analysis/diff-report.js';

describe('diffReport', () => {
  it('should detect new findings', async () => {
    const result = await diffReport({
      before: [],
      after: [{ tool: 'nmap', type: 'Open Port', severity: 'info', target: 'example.com' }],
    });
    expect(result.success).toBe(true);
    expect(result.summary.new).toBe(1);
    expect(result.summary.fixed).toBe(0);
  });

  it('should detect fixed findings', async () => {
    const result = await diffReport({
      before: [{ tool: 'nuclei', type: 'XSS', severity: 'high', target: 'example.com' }],
      after: [],
    });
    expect(result.success).toBe(true);
    expect(result.summary.fixed).toBe(1);
    expect(result.improvement).toBe(true);
  });

  it('should detect unchanged findings', async () => {
    const finding = { tool: 'nuclei', type: 'SQLi', severity: 'critical' as const, target: 'example.com' };
    const result = await diffReport({ before: [finding], after: [finding] });
    expect(result.summary.unchanged).toBe(1);
    expect(result.scoreChange).toBe('No change');
  });

  it('should detect upgraded severity', async () => {
    const result = await diffReport({
      before: [{ tool: 'x', type: 'Issue', severity: 'low', target: 't' }],
      after: [{ tool: 'x', type: 'Issue', severity: 'high', target: 't' }],
    });
    expect(result.summary.upgraded).toBe(1);
    expect(result.improvement).toBe(false);
  });

  it('should detect downgraded severity', async () => {
    const result = await diffReport({
      before: [{ tool: 'x', type: 'Issue', severity: 'critical', target: 't' }],
      after: [{ tool: 'x', type: 'Issue', severity: 'low', target: 't' }],
    });
    expect(result.summary.downgraded).toBe(1);
    expect(result.improvement).toBe(true);
  });

  it('should handle empty scans', async () => {
    const result = await diffReport({ before: [], after: [] });
    expect(result.success).toBe(true);
    expect(result.scoreChange).toBe('No change');
  });
});
