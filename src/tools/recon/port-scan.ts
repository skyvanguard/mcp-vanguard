import { z } from 'zod';
import { isInScope, getConfig } from '../../config.js';
import { executeWSL, checkWSLCommandExists } from '../../executor/wsl.js';
import { executeWindows, checkCommandExists } from '../../executor/windows.js';

export const portScanSchema = z.object({
  target: z.string().describe('Target IP or hostname'),
  ports: z.string().default('1-1000').describe('Port range (e.g., "22,80,443" or "1-1000")'),
  scanType: z.enum(['tcp', 'syn', 'udp']).default('tcp').describe('Scan type'),
  timeout: z.number().default(300000).describe('Timeout in milliseconds')
});

export type PortScanInput = z.infer<typeof portScanSchema>;

interface PortResult {
  port: number;
  state: 'open' | 'closed' | 'filtered';
  service?: string;
  version?: string;
}

export async function portScan(input: PortScanInput): Promise<{
  success: boolean;
  target: string;
  ports: PortResult[];
  scanType: string;
  duration?: number;
  error?: string;
}> {
  const { target, ports, scanType, timeout } = input;

  if (!isInScope(target)) {
    return {
      success: false,
      target,
      ports: [],
      scanType,
      error: `Target ${target} is not in scope. Use vanguard_set_scope to add it.`
    };
  }

  const startTime = Date.now();

  const nmapAvailableWindows = await checkCommandExists('nmap');

  if (nmapAvailableWindows) {
    return runNmapWindows(target, ports, scanType, timeout, startTime);
  }

  const config = getConfig();
  if (config.wslEnabled) {
    const nmapAvailableWSL = await checkWSLCommandExists('nmap');
    if (nmapAvailableWSL) {
      return runNmapWSL(target, ports, scanType, timeout, startTime);
    }
  }

  return runTcpConnect(target, ports, timeout, startTime);
}

async function runNmapWindows(
  target: string,
  ports: string,
  scanType: string,
  timeout: number,
  startTime: number
): Promise<{
  success: boolean;
  target: string;
  ports: PortResult[];
  scanType: string;
  duration: number;
  error?: string;
}> {
  const scanFlag = scanType === 'syn' ? '-sS' :
                   scanType === 'udp' ? '-sU' : '-sT';

  const args = [scanFlag, '-p', ports, '-oG', '-', '--open', target];

  const result = await executeWindows('nmap', args, { timeout });

  if (!result.success) {
    return {
      success: false,
      target,
      ports: [],
      scanType,
      duration: Date.now() - startTime,
      error: result.stderr || 'Nmap scan failed'
    };
  }

  const portResults = parseNmapGrepOutput(result.stdout);

  return {
    success: true,
    target,
    ports: portResults,
    scanType,
    duration: Date.now() - startTime
  };
}

async function runNmapWSL(
  target: string,
  ports: string,
  scanType: string,
  timeout: number,
  startTime: number
): Promise<{
  success: boolean;
  target: string;
  ports: PortResult[];
  scanType: string;
  duration: number;
  error?: string;
}> {
  const scanFlag = scanType === 'syn' ? '-sS' :
                   scanType === 'udp' ? '-sU' : '-sT';

  const result = await executeWSL(
    'nmap',
    [scanFlag, '-p', ports, '-oG', '-', '--open', target],
    { timeout }
  );

  if (!result.success) {
    return {
      success: false,
      target,
      ports: [],
      scanType,
      duration: Date.now() - startTime,
      error: result.stderr || 'Nmap scan failed'
    };
  }

  const portResults = parseNmapGrepOutput(result.stdout);

  return {
    success: true,
    target,
    ports: portResults,
    scanType,
    duration: Date.now() - startTime
  };
}

function parseNmapGrepOutput(output: string): PortResult[] {
  const results: PortResult[] = [];

  const portPattern = /(\d+)\/open\/tcp\/\/([^/]*)/g;
  let match;

  while ((match = portPattern.exec(output)) !== null) {
    results.push({
      port: parseInt(match[1], 10),
      state: 'open',
      service: match[2] || undefined
    });
  }

  return results;
}

async function runTcpConnect(
  target: string,
  portsSpec: string,
  timeout: number,
  startTime: number
): Promise<{
  success: boolean;
  target: string;
  ports: PortResult[];
  scanType: string;
  duration: number;
  error?: string;
}> {
  const portList = parsePortSpec(portsSpec);
  const results: PortResult[] = [];

  const batchSize = 50;
  const perPortTimeout = Math.min(2000, Math.floor(timeout / portList.length));

  for (let i = 0; i < portList.length; i += batchSize) {
    const batch = portList.slice(i, i + batchSize);
    const batchResults = await Promise.all(
      batch.map(port => checkPortOpen(target, port, perPortTimeout))
    );

    for (let j = 0; j < batch.length; j++) {
      if (batchResults[j]) {
        results.push({
          port: batch[j],
          state: 'open'
        });
      }
    }

    if (Date.now() - startTime > timeout) {
      break;
    }
  }

  return {
    success: true,
    target,
    ports: results,
    scanType: 'tcp_connect',
    duration: Date.now() - startTime
  };
}

function parsePortSpec(spec: string): number[] {
  const ports: number[] = [];

  const parts = spec.split(',');
  for (const part of parts) {
    if (part.includes('-')) {
      const [start, end] = part.split('-').map(Number);
      for (let p = start; p <= end && p <= 65535; p++) {
        ports.push(p);
      }
    } else {
      const p = parseInt(part, 10);
      if (p > 0 && p <= 65535) {
        ports.push(p);
      }
    }
  }

  return ports;
}

async function checkPortOpen(host: string, port: number, timeout: number): Promise<boolean> {
  return new Promise((resolve) => {
    const net = require('net');
    const socket = new net.Socket();

    socket.setTimeout(timeout);

    socket.on('connect', () => {
      socket.destroy();
      resolve(true);
    });

    socket.on('timeout', () => {
      socket.destroy();
      resolve(false);
    });

    socket.on('error', () => {
      socket.destroy();
      resolve(false);
    });

    socket.connect(port, host);
  });
}
