import { z } from 'zod';

export const timelineSchema = z.object({
  events: z.array(z.object({
    timestamp: z.string().describe('ISO timestamp or relative time'),
    tool: z.string(),
    action: z.string(),
    target: z.string(),
    result: z.enum(['success', 'failure', 'blocked']),
    details: z.string().optional(),
  })).describe('Pentest events to organize into timeline'),
  format: z.enum(['chronological', 'by_target', 'by_phase']).default('chronological'),
});

export type TimelineInput = z.infer<typeof timelineSchema>;

interface TimelineEntry {
  time: string;
  phase: string;
  tool: string;
  action: string;
  target: string;
  result: string;
  details?: string;
}

const TOOL_PHASES: Record<string, string> = {
  vanguard_dns_records: 'Reconnaissance',
  vanguard_whois: 'Reconnaissance',
  vanguard_cert_search: 'Reconnaissance',
  vanguard_port_scan: 'Scanning',
  vanguard_service_detect: 'Scanning',
  vanguard_nuclei_scan: 'Vulnerability Assessment',
  vanguard_sqli_test: 'Exploitation',
  vanguard_xss_test: 'Exploitation',
  vanguard_ssrf_test: 'Exploitation',
  vanguard_lfi_test: 'Exploitation',
  vanguard_command_inject_test: 'Exploitation',
  vanguard_hash_crack: 'Post-Exploitation',
  vanguard_jwt_attack: 'Post-Exploitation',
  vanguard_container_escape: 'Post-Exploitation',
};

export async function timeline(input: TimelineInput): Promise<{
  success: boolean;
  timeline: TimelineEntry[];
  phases: Array<{ phase: string; count: number; successRate: number }>;
  duration?: string;
  format: string;
}> {
  const { events, format } = input;

  const entries: TimelineEntry[] = events.map(e => ({
    time: e.timestamp,
    phase: TOOL_PHASES[e.tool] || categorizeAction(e.action),
    tool: e.tool,
    action: e.action,
    target: e.target,
    result: e.result,
    details: e.details,
  }));

  // Sort
  if (format === 'chronological') {
    entries.sort((a, b) => a.time.localeCompare(b.time));
  } else if (format === 'by_target') {
    entries.sort((a, b) => a.target.localeCompare(b.target) || a.time.localeCompare(b.time));
  } else if (format === 'by_phase') {
    const phaseOrder = ['Reconnaissance', 'Scanning', 'Vulnerability Assessment', 'Exploitation', 'Post-Exploitation', 'Reporting'];
    entries.sort((a, b) => {
      const aIdx = phaseOrder.indexOf(a.phase);
      const bIdx = phaseOrder.indexOf(b.phase);
      return (aIdx === -1 ? 99 : aIdx) - (bIdx === -1 ? 99 : bIdx) || a.time.localeCompare(b.time);
    });
  }

  // Phase summary
  const phaseMap = new Map<string, { total: number; success: number }>();
  for (const e of entries) {
    const p = phaseMap.get(e.phase) || { total: 0, success: 0 };
    p.total++;
    if (e.result === 'success') p.success++;
    phaseMap.set(e.phase, p);
  }

  const phases = [...phaseMap.entries()].map(([phase, stats]) => ({
    phase,
    count: stats.total,
    successRate: Math.round((stats.success / stats.total) * 100),
  }));

  // Duration
  let duration: string | undefined;
  if (entries.length >= 2) {
    const first = new Date(entries[0].time).getTime();
    const last = new Date(entries[entries.length - 1].time).getTime();
    if (!isNaN(first) && !isNaN(last)) {
      const diffMs = last - first;
      const mins = Math.round(diffMs / 60000);
      duration = mins < 60 ? `${mins} minutes` : `${Math.round(mins / 60)} hours ${mins % 60} minutes`;
    }
  }

  return {
    success: true,
    timeline: entries,
    phases,
    duration,
    format,
  };
}

function categorizeAction(action: string): string {
  const lower = action.toLowerCase();
  if (lower.includes('scan') || lower.includes('enum')) return 'Scanning';
  if (lower.includes('exploit') || lower.includes('inject') || lower.includes('test')) return 'Exploitation';
  if (lower.includes('crack') || lower.includes('dump')) return 'Post-Exploitation';
  if (lower.includes('recon') || lower.includes('lookup') || lower.includes('discover')) return 'Reconnaissance';
  return 'Other';
}
