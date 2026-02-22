import { z } from 'zod';
import { isInScope, getConfig } from '../../config.js';
import { executeWSL, checkWSLCommandExists } from '../../executor/wsl.js';

export const arpScanSchema = z.object({
  target: z.string().describe('Target network range (e.g., "192.168.1.0/24")'),
  interface: z.string().optional().describe('Network interface to use'),
  timeout: z.number().default(60000).describe('Timeout in milliseconds')
});

export type ArpScanInput = z.infer<typeof arpScanSchema>;

interface ArpEntry {
  ip: string;
  mac: string;
  vendor?: string;
}

export async function arpScan(input: ArpScanInput): Promise<{
  success: boolean;
  target: string;
  hosts: ArpEntry[];
  totalFound: number;
  error?: string;
}> {
  const { target, timeout } = input;
  const iface = input.interface;

  if (!isInScope(target)) {
    return {
      success: false,
      target,
      hosts: [],
      totalFound: 0,
      error: `Target ${target} is not in scope. Use vanguard_set_scope first.`
    };
  }

  const config = getConfig();
  if (!config.wslEnabled) {
    return { success: false, target, hosts: [], totalFound: 0, error: 'WSL required for ARP scan' };
  }

  const arpAvailable = await checkWSLCommandExists('arp-scan');
  if (!arpAvailable) {
    return { success: false, target, hosts: [], totalFound: 0, error: 'arp-scan not found in WSL. Install: apt install arp-scan' };
  }

  const args = ['--localnet'];
  if (target !== 'localnet') {
    args.length = 0;
    args.push(target);
  }
  if (iface) {
    args.push('-I', iface);
  }

  const result = await executeWSL('arp-scan', args, { timeout });

  if (!result.success && !result.stdout) {
    return { success: false, target, hosts: [], totalFound: 0, error: result.stderr || 'ARP scan failed' };
  }

  const hosts = parseArpScanOutput(result.stdout);
  return { success: true, target, hosts, totalFound: hosts.length };
}

function parseArpScanOutput(output: string): ArpEntry[] {
  const entries: ArpEntry[] = [];
  const lines = output.split('\n');

  for (const line of lines) {
    const match = line.match(/^(\d+\.\d+\.\d+\.\d+)\s+([0-9a-f:]{17})\s*(.*)/i);
    if (match) {
      entries.push({
        ip: match[1],
        mac: match[2],
        vendor: match[3]?.trim() || undefined
      });
    }
  }

  return entries;
}
