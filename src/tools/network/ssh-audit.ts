import { z } from 'zod';
import * as net from 'net';
import { isInScope, getConfig } from '../../config.js';
import { executeWSL, checkWSLCommandExists } from '../../executor/wsl.js';

export const sshAuditSchema = z.object({
  target: z.string().describe('Target IP or hostname'),
  port: z.number().default(22).describe('SSH port'),
  timeout: z.number().default(15000).describe('Timeout in milliseconds')
});

export type SshAuditInput = z.infer<typeof sshAuditSchema>;

interface SshAuditResult {
  banner: string | null;
  protocol?: string;
  kex?: string[];
  hostKeys?: string[];
  ciphers?: string[];
  macs?: string[];
  warnings: string[];
}

export async function sshAudit(input: SshAuditInput): Promise<{
  success: boolean;
  target: string;
  port: number;
  result: SshAuditResult;
  error?: string;
}> {
  const { target, port, timeout } = input;

  if (!isInScope(target)) {
    return {
      success: false,
      target,
      port,
      result: { banner: null, warnings: [] },
      error: `Target ${target} is not in scope. Use vanguard_set_scope first.`
    };
  }

  const config = getConfig();

  // Try ssh-audit tool in WSL
  if (config.wslEnabled) {
    const sshAuditAvailable = await checkWSLCommandExists('ssh-audit');
    if (sshAuditAvailable) {
      const result = await executeWSL('ssh-audit', ['-p', String(port), target], { timeout });
      if (result.success || result.stdout) {
        return { success: true, target, port, result: parseSshAuditOutput(result.stdout) };
      }
    }
  }

  // Fallback: basic banner grab
  try {
    const banner = await grabSshBanner(target, port, timeout);
    const warnings: string[] = [];

    if (banner) {
      if (banner.includes('SSH-1')) warnings.push('SSHv1 protocol detected - vulnerable');
      if (banner.match(/OpenSSH[_ ]([1-6])\./)) warnings.push('Outdated OpenSSH version detected');
      if (banner.match(/dropbear/i)) warnings.push('Dropbear SSH detected - check version');
    }

    return {
      success: true,
      target,
      port,
      result: {
        banner,
        protocol: banner?.match(/SSH-(\d+\.\d+)/)?.[1] || undefined,
        warnings
      }
    };
  } catch (err) {
    return {
      success: false,
      target,
      port,
      result: { banner: null, warnings: [] },
      error: err instanceof Error ? err.message : 'SSH audit failed'
    };
  }
}

function parseSshAuditOutput(output: string): SshAuditResult {
  const result: SshAuditResult = { banner: null, warnings: [] };
  const lines = output.split('\n');

  for (const line of lines) {
    if (line.includes('banner:')) {
      result.banner = line.split('banner:')[1]?.trim() || null;
    }
    if (line.includes('(kex)')) {
      if (!result.kex) result.kex = [];
      result.kex.push(line.trim());
    }
    if (line.includes('(key)')) {
      if (!result.hostKeys) result.hostKeys = [];
      result.hostKeys.push(line.trim());
    }
    if (line.includes('(enc)')) {
      if (!result.ciphers) result.ciphers = [];
      result.ciphers.push(line.trim());
    }
    if (line.includes('(mac)')) {
      if (!result.macs) result.macs = [];
      result.macs.push(line.trim());
    }
    if (line.includes('-- [warn]') || line.includes('-- [fail]')) {
      result.warnings.push(line.trim());
    }
  }

  return result;
}

function grabSshBanner(host: string, port: number, timeout: number): Promise<string | null> {
  return new Promise((resolve, reject) => {
    const socket = new net.Socket();
    socket.setTimeout(timeout);

    socket.on('data', (data) => {
      const banner = data.toString().trim();
      socket.destroy();
      resolve(banner);
    });

    socket.on('timeout', () => {
      socket.destroy();
      resolve(null);
    });

    socket.on('error', (err) => {
      socket.destroy();
      reject(err);
    });

    socket.connect(port, host);
  });
}
