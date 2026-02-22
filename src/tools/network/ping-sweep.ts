import { z } from 'zod';
import { isInScope, getConfig } from '../../config.js';
import { executeWSL, checkWSLCommandExists } from '../../executor/wsl.js';
import { executeWindows, checkCommandExists } from '../../executor/windows.js';

export const pingSweepSchema = z.object({
  target: z.string().describe('Target CIDR range or IP (e.g., "192.168.1.0/24")'),
  timeout: z.number().default(120000).describe('Timeout in milliseconds')
});

export type PingSweepInput = z.infer<typeof pingSweepSchema>;

interface HostResult {
  ip: string;
  alive: boolean;
  hostname?: string;
  latency?: string;
}

export async function pingSweep(input: PingSweepInput): Promise<{
  success: boolean;
  target: string;
  hosts: HostResult[];
  totalAlive: number;
  error?: string;
}> {
  const { target, timeout } = input;

  if (!isInScope(target)) {
    return {
      success: false,
      target,
      hosts: [],
      totalAlive: 0,
      error: `Target ${target} is not in scope. Use vanguard_set_scope first.`
    };
  }

  const config = getConfig();

  // Try nmap on Windows
  const nmapWindows = await checkCommandExists('nmap');
  if (nmapWindows) {
    const result = await executeWindows('nmap', ['-sn', '-oG', '-', target], { timeout });
    if (result.success || result.stdout) {
      const hosts = parseNmapPingSweep(result.stdout);
      return { success: true, target, hosts, totalAlive: hosts.filter(h => h.alive).length };
    }
  }

  // Try nmap in WSL
  if (config.wslEnabled) {
    const nmapWSL = await checkWSLCommandExists('nmap');
    if (nmapWSL) {
      const result = await executeWSL('nmap', ['-sn', '-oG', '-', target], { timeout });
      if (result.success || result.stdout) {
        const hosts = parseNmapPingSweep(result.stdout);
        return { success: true, target, hosts, totalAlive: hosts.filter(h => h.alive).length };
      }
      return { success: false, target, hosts: [], totalAlive: 0, error: result.stderr || 'Ping sweep failed' };
    }
  }

  return { success: false, target, hosts: [], totalAlive: 0, error: 'nmap not available on Windows or WSL' };
}

function parseNmapPingSweep(output: string): HostResult[] {
  const hosts: HostResult[] = [];
  const lines = output.split('\n');

  for (const line of lines) {
    const hostMatch = line.match(/Host:\s+(\S+)\s+\(([^)]*)\)\s+Status:\s+(\w+)/);
    if (hostMatch) {
      hosts.push({
        ip: hostMatch[1],
        alive: hostMatch[3].toLowerCase() === 'up',
        hostname: hostMatch[2] || undefined
      });
    }
  }

  return hosts;
}
