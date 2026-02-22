import { z } from 'zod';
import { isInScope, getConfig } from '../../config.js';
import { executeWSL, checkWSLCommandExists } from '../../executor/wsl.js';
import { executeWindows, checkCommandExists } from '../../executor/windows.js';

export const serviceDetectSchema = z.object({
  target: z.string().describe('Target IP or hostname'),
  ports: z.string().default('21,22,25,53,80,110,143,443,445,993,995,3306,3389,5432,8080,8443')
    .describe('Ports to detect services on'),
  intensity: z.number().min(0).max(9).default(7).describe('Service detection intensity (0-9)'),
  timeout: z.number().default(300000).describe('Timeout in milliseconds')
});

export type ServiceDetectInput = z.infer<typeof serviceDetectSchema>;

interface ServiceResult {
  port: number;
  protocol: string;
  state: string;
  service: string;
  version?: string;
  extraInfo?: string;
}

export async function serviceDetect(input: ServiceDetectInput): Promise<{
  success: boolean;
  target: string;
  services: ServiceResult[];
  error?: string;
}> {
  const { target, ports, intensity, timeout } = input;

  if (!isInScope(target)) {
    return {
      success: false,
      target,
      services: [],
      error: `Target ${target} is not in scope. Use vanguard_set_scope first.`
    };
  }

  const config = getConfig();
  const args = ['-sV', `--version-intensity`, String(intensity), '-p', ports, '-oG', '-', target];

  // Try Windows nmap
  const nmapWindows = await checkCommandExists('nmap');
  if (nmapWindows) {
    const result = await executeWindows('nmap', args, { timeout });
    if (result.success || result.stdout) {
      return { success: true, target, services: parseServiceOutput(result.stdout) };
    }
  }

  // Try WSL nmap
  if (config.wslEnabled) {
    const nmapWSL = await checkWSLCommandExists('nmap');
    if (nmapWSL) {
      const result = await executeWSL('nmap', args, { timeout });
      if (result.success || result.stdout) {
        return { success: true, target, services: parseServiceOutput(result.stdout) };
      }
      return { success: false, target, services: [], error: result.stderr || 'Service detection failed' };
    }
  }

  return { success: false, target, services: [], error: 'nmap not available' };
}

function parseServiceOutput(output: string): ServiceResult[] {
  const services: ServiceResult[] = [];

  // Parse greppable nmap output for services
  const portPattern = /(\d+)\/(open|filtered)\/(tcp|udp)\/\/([^/]*)\/?([^/]*)?/g;
  let match;

  while ((match = portPattern.exec(output)) !== null) {
    services.push({
      port: parseInt(match[1], 10),
      state: match[2],
      protocol: match[3],
      service: match[4] || 'unknown',
      version: match[5] || undefined
    });
  }

  return services;
}
