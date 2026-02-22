import { z } from 'zod';
import { isInScope, getConfig } from '../../config.js';
import { executeWSL, checkWSLCommandExists } from '../../executor/wsl.js';
import { executeWindows, checkCommandExists } from '../../executor/windows.js';

export const tracerouteSchema = z.object({
  target: z.string().describe('Target IP or hostname to trace'),
  maxHops: z.number().default(30).describe('Maximum number of hops'),
  timeout: z.number().default(60000).describe('Timeout in milliseconds')
});

export type TracerouteInput = z.infer<typeof tracerouteSchema>;

interface TracerouteHop {
  hop: number;
  ip: string | null;
  hostname?: string;
  rtt?: string[];
}

export async function traceroute(input: TracerouteInput): Promise<{
  success: boolean;
  target: string;
  hops: TracerouteHop[];
  error?: string;
}> {
  const { target, maxHops, timeout } = input;

  if (!isInScope(target)) {
    return {
      success: false,
      target,
      hops: [],
      error: `Target ${target} is not in scope. Use vanguard_set_scope first.`
    };
  }

  const config = getConfig();

  // Try Windows tracert first
  const tracertAvailable = await checkCommandExists('tracert');
  if (tracertAvailable) {
    const result = await executeWindows('tracert', ['-h', String(maxHops), '-w', '1000', target], { timeout });
    if (result.success || result.stdout) {
      return {
        success: true,
        target,
        hops: parseTracertOutput(result.stdout)
      };
    }
  }

  // Try WSL traceroute
  if (config.wslEnabled) {
    const trAvailable = await checkWSLCommandExists('traceroute');
    if (trAvailable) {
      const result = await executeWSL('traceroute', ['-m', String(maxHops), '-w', '1', target], { timeout });
      if (result.success || result.stdout) {
        return {
          success: true,
          target,
          hops: parseTracerouteOutput(result.stdout)
        };
      }
      return { success: false, target, hops: [], error: result.stderr || 'Traceroute failed' };
    }
  }

  return { success: false, target, hops: [], error: 'Neither tracert (Windows) nor traceroute (WSL) available' };
}

function parseTracertOutput(output: string): TracerouteHop[] {
  const hops: TracerouteHop[] = [];
  const lines = output.split('\n');

  for (const line of lines) {
    const match = line.match(/^\s*(\d+)\s+([\s\S]+)/);
    if (!match) continue;

    const hop = parseInt(match[1], 10);
    const rest = match[2];

    if (rest.includes('Request timed out') || rest.includes('* * *')) {
      hops.push({ hop, ip: null, rtt: ['*', '*', '*'] });
      continue;
    }

    const ipMatch = rest.match(/(\d+\.\d+\.\d+\.\d+)/);
    const hostnameMatch = rest.match(/([a-zA-Z][\w.-]+)\s+\[?\d+\.\d+/);
    const rttMatches = rest.match(/(\d+)\s*ms/g);

    hops.push({
      hop,
      ip: ipMatch ? ipMatch[1] : null,
      hostname: hostnameMatch ? hostnameMatch[1] : undefined,
      rtt: rttMatches || undefined
    });
  }

  return hops;
}

function parseTracerouteOutput(output: string): TracerouteHop[] {
  const hops: TracerouteHop[] = [];
  const lines = output.split('\n');

  for (const line of lines) {
    const match = line.match(/^\s*(\d+)\s+([\s\S]+)/);
    if (!match) continue;

    const hop = parseInt(match[1], 10);
    const rest = match[2];

    if (rest.trim() === '* * *') {
      hops.push({ hop, ip: null, rtt: ['*', '*', '*'] });
      continue;
    }

    const ipMatch = rest.match(/\((\d+\.\d+\.\d+\.\d+)\)/);
    const hostnameMatch = rest.match(/^([a-zA-Z][\w.-]+)/);
    const rttMatches = rest.match(/([\d.]+)\s*ms/g);

    hops.push({
      hop,
      ip: ipMatch ? ipMatch[1] : null,
      hostname: hostnameMatch ? hostnameMatch[1] : undefined,
      rtt: rttMatches || undefined
    });
  }

  return hops;
}
