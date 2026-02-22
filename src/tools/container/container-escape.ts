import { z } from 'zod';
import { getConfig } from '../../config.js';
import { executeWSL, checkWSLCommandExists } from '../../executor/wsl.js';

export const containerEscapeSchema = z.object({
  checks: z.array(z.enum([
    'docker_socket', 'privileged', 'capabilities', 'procfs',
    'cgroups', 'namespaces', 'mounted_dirs', 'env_vars',
  ])).default(['docker_socket', 'privileged', 'capabilities', 'procfs', 'cgroups', 'mounted_dirs', 'env_vars'])
    .describe('Escape vector checks to perform'),
  timeout: z.number().default(15000).describe('Timeout in milliseconds'),
});

export type ContainerEscapeInput = z.infer<typeof containerEscapeSchema>;

interface EscapeCheck {
  check: string;
  vulnerable: boolean;
  details: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
}

export async function containerEscape(input: ContainerEscapeInput): Promise<{
  success: boolean;
  isContainer: boolean;
  results: EscapeCheck[];
  escapeVectors: number;
  error?: string;
}> {
  const { checks, timeout } = input;
  const config = getConfig();
  const results: EscapeCheck[] = [];

  if (!config.wslEnabled) {
    return { success: false, isContainer: false, results: [], escapeVectors: 0, error: 'WSL required for container escape checks (run inside container via WSL)' };
  }

  // Check if we're in a container
  const isContainer = await checkIfContainer(timeout);

  if (!isContainer) {
    return {
      success: true,
      isContainer: false,
      results: [{ check: 'container_detection', vulnerable: false, details: 'Not running inside a container', severity: 'info' }],
      escapeVectors: 0,
    };
  }

  for (const check of checks) {
    switch (check) {
      case 'docker_socket': {
        const r = await runCheck('ls -la /var/run/docker.sock 2>/dev/null', timeout);
        results.push({
          check: 'Docker Socket Mounted',
          vulnerable: r.includes('docker.sock'),
          details: r.includes('docker.sock') ? 'Docker socket accessible — full host control possible' : 'Docker socket not mounted',
          severity: 'critical',
        });
        break;
      }
      case 'privileged': {
        const r = await runCheck('cat /proc/1/status 2>/dev/null | grep -i cap', timeout);
        const fullCaps = r.includes('0000003fffffffff') || r.includes('000001ffffffffff');
        results.push({
          check: 'Privileged Mode',
          vulnerable: fullCaps,
          details: fullCaps ? 'Container appears to run in privileged mode (all capabilities)' : 'Not running in privileged mode',
          severity: 'critical',
        });
        break;
      }
      case 'capabilities': {
        const r = await runCheck('cat /proc/1/status 2>/dev/null | grep CapEff', timeout);
        const caps = r.match(/CapEff:\s+([0-9a-f]+)/i);
        const dangerousCaps = caps ? parseInt(caps[1], 16) : 0;
        const hasSysAdmin = (dangerousCaps & 0x200000) !== 0; // CAP_SYS_ADMIN
        results.push({
          check: 'Dangerous Capabilities',
          vulnerable: hasSysAdmin,
          details: hasSysAdmin ? 'CAP_SYS_ADMIN detected — mount/cgroup escape possible' : `Capabilities: ${caps?.[1] || 'unknown'}`,
          severity: hasSysAdmin ? 'high' : 'info',
        });
        break;
      }
      case 'procfs': {
        const r = await runCheck('ls /proc/sysrq-trigger 2>/dev/null && echo ACCESSIBLE', timeout);
        results.push({
          check: 'Host procfs Accessible',
          vulnerable: r.includes('ACCESSIBLE'),
          details: r.includes('ACCESSIBLE') ? '/proc/sysrq-trigger accessible — host kernel interaction possible' : 'procfs properly restricted',
          severity: 'high',
        });
        break;
      }
      case 'cgroups': {
        const r = await runCheck('mount | grep cgroup 2>/dev/null', timeout);
        const writable = r.includes('rw,');
        results.push({
          check: 'Writable cgroups',
          vulnerable: writable,
          details: writable ? 'Writable cgroup mounts found — cgroup escape possible' : 'cgroups appear read-only',
          severity: 'high',
        });
        break;
      }
      case 'mounted_dirs': {
        const r = await runCheck('mount 2>/dev/null | grep -E "/(etc|root|home|var)" | head -10', timeout);
        const hasMounts = r.trim().length > 0;
        results.push({
          check: 'Sensitive Host Mounts',
          vulnerable: hasMounts,
          details: hasMounts ? `Sensitive host directories mounted:\n${r.trim().slice(0, 300)}` : 'No sensitive host mounts detected',
          severity: hasMounts ? 'high' : 'info',
        });
        break;
      }
      case 'env_vars': {
        const r = await runCheck('env 2>/dev/null | grep -iE "(password|secret|token|key|api)" | head -5', timeout);
        const hasSecrets = r.trim().length > 0;
        results.push({
          check: 'Secrets in Environment',
          vulnerable: hasSecrets,
          details: hasSecrets ? `Secrets found in environment variables (${r.trim().split('\n').length} matches)` : 'No obvious secrets in environment',
          severity: hasSecrets ? 'medium' : 'info',
        });
        break;
      }
    }
  }

  return {
    success: true,
    isContainer: true,
    results,
    escapeVectors: results.filter(r => r.vulnerable).length,
  };
}

async function checkIfContainer(timeout: number): Promise<boolean> {
  const r = await runCheck('cat /proc/1/cgroup 2>/dev/null; ls /.dockerenv 2>/dev/null', timeout);
  return r.includes('docker') || r.includes('kubepods') || r.includes('.dockerenv') || r.includes('containerd');
}

async function runCheck(cmd: string, timeout: number): Promise<string> {
  try {
    const result = await executeWSL('bash', ['-c', cmd], { timeout });
    return result.stdout || '';
  } catch {
    return '';
  }
}
