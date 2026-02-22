import { z } from 'zod';
import { getConfig } from '../../config.js';
import { executeWSL, checkWSLCommandExists } from '../../executor/wsl.js';

export const helmAuditSchema = z.object({
  chart: z.string().optional().describe('Helm chart path or release name to audit'),
  values: z.string().optional().describe('Path to values.yaml file to analyze'),
  timeout: z.number().default(30000).describe('Timeout in milliseconds'),
});

export type HelmAuditInput = z.infer<typeof helmAuditSchema>;

interface HelmIssue {
  category: string;
  issue: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  recommendation: string;
}

const SECURITY_PATTERNS: Array<{ pattern: RegExp; category: string; issue: string; severity: HelmIssue['severity']; recommendation: string }> = [
  { pattern: /privileged:\s*true/i, category: 'container', issue: 'Privileged container', severity: 'critical', recommendation: 'Set privileged: false' },
  { pattern: /hostNetwork:\s*true/i, category: 'network', issue: 'Host network mode', severity: 'high', recommendation: 'Disable hostNetwork unless necessary' },
  { pattern: /hostPID:\s*true/i, category: 'isolation', issue: 'Host PID namespace', severity: 'high', recommendation: 'Disable hostPID' },
  { pattern: /hostIPC:\s*true/i, category: 'isolation', issue: 'Host IPC namespace', severity: 'high', recommendation: 'Disable hostIPC' },
  { pattern: /runAsUser:\s*0\b/i, category: 'container', issue: 'Running as root (UID 0)', severity: 'high', recommendation: 'Set runAsUser to non-root UID' },
  { pattern: /readOnlyRootFilesystem:\s*false/i, category: 'filesystem', issue: 'Writable root filesystem', severity: 'medium', recommendation: 'Set readOnlyRootFilesystem: true' },
  { pattern: /allowPrivilegeEscalation:\s*true/i, category: 'container', issue: 'Privilege escalation allowed', severity: 'high', recommendation: 'Set allowPrivilegeEscalation: false' },
  { pattern: /SYS_ADMIN|NET_ADMIN|NET_RAW|ALL/i, category: 'capabilities', issue: 'Dangerous capabilities', severity: 'high', recommendation: 'Drop all capabilities, add only what is needed' },
  { pattern: /password|secret|token|api.?key/i, category: 'secrets', issue: 'Hardcoded secrets in values', severity: 'critical', recommendation: 'Use Kubernetes Secrets or external secret management' },
  { pattern: /hostPath:/i, category: 'volumes', issue: 'hostPath volume mount', severity: 'medium', recommendation: 'Avoid hostPath volumes; use PV/PVC instead' },
  { pattern: /emptyDir:\s*\{?\s*medium:\s*Memory/i, category: 'resources', issue: 'Memory-backed emptyDir without limit', severity: 'low', recommendation: 'Set sizeLimit on memory-backed emptyDir' },
  { pattern: /type:\s*LoadBalancer/i, category: 'network', issue: 'Public LoadBalancer service', severity: 'info', recommendation: 'Verify LoadBalancer is intentionally public' },
];

export async function helmAudit(input: HelmAuditInput): Promise<{
  success: boolean;
  issues: HelmIssue[];
  source: string;
  error?: string;
}> {
  const { chart, values, timeout } = input;

  // Try to get template output from Helm
  let content = '';
  let source = '';
  const config = getConfig();

  if (chart && config.wslEnabled) {
    const helmExists = await checkWSLCommandExists('helm');
    if (helmExists) {
      // Try helm template
      const result = await executeWSL('helm', ['template', 'audit-check', chart, '--dry-run'], { timeout });
      if (result.success || result.stdout) {
        content = result.stdout || '';
        source = `helm template ${chart}`;
      }

      // Try helm get values for deployed release
      if (!content) {
        const getResult = await executeWSL('helm', ['get', 'values', chart, '-a'], { timeout });
        if (getResult.success || getResult.stdout) {
          content = getResult.stdout || '';
          source = `helm get values ${chart}`;
        }
      }
    }
  }

  // If we have a values file path, read it via WSL
  if (!content && values && config.wslEnabled) {
    const catResult = await executeWSL('cat', [values], { timeout: 5000 });
    if (catResult.success || catResult.stdout) {
      content = catResult.stdout || '';
      source = `values file: ${values}`;
    }
  }

  if (!content) {
    return {
      success: false,
      issues: [],
      source: 'none',
      error: 'No content to audit. Provide a chart name (deployed release) or values file path. Requires helm in WSL.',
    };
  }

  // Analyze content
  const issues: HelmIssue[] = [];

  for (const sp of SECURITY_PATTERNS) {
    if (sp.pattern.test(content)) {
      issues.push({
        category: sp.category,
        issue: sp.issue,
        severity: sp.severity,
        recommendation: sp.recommendation,
      });
    }
  }

  // Check for missing security context
  if (!content.includes('securityContext')) {
    issues.push({
      category: 'container',
      issue: 'Missing securityContext',
      severity: 'medium',
      recommendation: 'Add securityContext with runAsNonRoot, readOnlyRootFilesystem, drop capabilities',
    });
  }

  // Check for missing resource limits
  if (!content.includes('resources:') || !content.includes('limits:')) {
    issues.push({
      category: 'resources',
      issue: 'Missing resource limits',
      severity: 'medium',
      recommendation: 'Set CPU and memory limits to prevent resource exhaustion',
    });
  }

  // Check for missing network policy
  if (!content.includes('NetworkPolicy')) {
    issues.push({
      category: 'network',
      issue: 'No NetworkPolicy defined',
      severity: 'low',
      recommendation: 'Define NetworkPolicy to restrict pod-to-pod traffic',
    });
  }

  if (issues.length === 0) {
    issues.push({
      category: 'general',
      issue: 'No issues detected',
      severity: 'info',
      recommendation: 'Configuration appears secure. Consider deeper analysis with kube-bench or kubescape.',
    });
  }

  return {
    success: true,
    issues,
    source,
  };
}
