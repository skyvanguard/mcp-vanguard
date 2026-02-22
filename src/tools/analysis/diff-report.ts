import { z } from 'zod';

export const diffReportSchema = z.object({
  before: z.array(z.object({
    tool: z.string(),
    type: z.string(),
    severity: z.enum(['info', 'low', 'medium', 'high', 'critical']),
    target: z.string(),
  })).describe('Findings from previous scan'),
  after: z.array(z.object({
    tool: z.string(),
    type: z.string(),
    severity: z.enum(['info', 'low', 'medium', 'high', 'critical']),
    target: z.string(),
  })).describe('Findings from current scan'),
});

export type DiffReportInput = z.infer<typeof diffReportSchema>;

interface DiffEntry {
  status: 'new' | 'fixed' | 'unchanged' | 'upgraded' | 'downgraded';
  type: string;
  target: string;
  severity: string;
  previousSeverity?: string;
}

export async function diffReport(input: DiffReportInput): Promise<{
  success: boolean;
  diff: DiffEntry[];
  summary: { new: number; fixed: number; unchanged: number; upgraded: number; downgraded: number };
  improvement: boolean;
  scoreChange: string;
}> {
  const { before, after } = input;
  const diff: DiffEntry[] = [];

  const severityValue: Record<string, number> = { critical: 5, high: 4, medium: 3, low: 2, info: 1 };

  // Key: type+target
  const beforeMap = new Map<string, (typeof before)[0]>();
  for (const f of before) {
    beforeMap.set(`${f.type}|${f.target}`, f);
  }
  const afterMap = new Map<string, (typeof after)[0]>();
  for (const f of after) {
    afterMap.set(`${f.type}|${f.target}`, f);
  }

  // Check after findings
  for (const [key, f] of afterMap) {
    const prev = beforeMap.get(key);
    if (!prev) {
      diff.push({ status: 'new', type: f.type, target: f.target, severity: f.severity });
    } else if (prev.severity === f.severity) {
      diff.push({ status: 'unchanged', type: f.type, target: f.target, severity: f.severity });
    } else if ((severityValue[f.severity] || 0) > (severityValue[prev.severity] || 0)) {
      diff.push({ status: 'upgraded', type: f.type, target: f.target, severity: f.severity, previousSeverity: prev.severity });
    } else {
      diff.push({ status: 'downgraded', type: f.type, target: f.target, severity: f.severity, previousSeverity: prev.severity });
    }
  }

  // Check fixed (in before but not after)
  for (const [key, f] of beforeMap) {
    if (!afterMap.has(key)) {
      diff.push({ status: 'fixed', type: f.type, target: f.target, severity: f.severity });
    }
  }

  const summary = { new: 0, fixed: 0, unchanged: 0, upgraded: 0, downgraded: 0 };
  for (const d of diff) summary[d.status]++;

  const beforeScore = before.reduce((s, f) => s + (severityValue[f.severity] || 0), 0);
  const afterScore = after.reduce((s, f) => s + (severityValue[f.severity] || 0), 0);
  const improvement = afterScore < beforeScore;
  const change = afterScore - beforeScore;

  return {
    success: true,
    diff,
    summary,
    improvement,
    scoreChange: change === 0 ? 'No change' : change > 0 ? `+${change} (worse)` : `${change} (improved)`,
  };
}
