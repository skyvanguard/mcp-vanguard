import { z } from 'zod';
import { isInScope, getConfig } from '../../config.js';
import { executeWSL, checkWSLCommandExists } from '../../executor/wsl.js';

export const smbEnumSchema = z.object({
  target: z.string().describe('Target IP or hostname'),
  username: z.string().default('').describe('Username for authentication (empty for null session)'),
  password: z.string().default('').describe('Password for authentication'),
  timeout: z.number().default(120000).describe('Timeout in milliseconds')
});

export type SmbEnumInput = z.infer<typeof smbEnumSchema>;

interface SmbShare {
  name: string;
  type: string;
  comment?: string;
  access?: string;
}

interface SmbEnumResult {
  shares: SmbShare[];
  users: string[];
  osInfo?: string;
  workgroup?: string;
}

export async function smbEnum(input: SmbEnumInput): Promise<{
  success: boolean;
  target: string;
  result: SmbEnumResult;
  error?: string;
}> {
  const { target, username, password, timeout } = input;

  if (!isInScope(target)) {
    return {
      success: false,
      target,
      result: { shares: [], users: [] },
      error: `Target ${target} is not in scope. Use vanguard_set_scope first.`
    };
  }

  const config = getConfig();
  if (!config.wslEnabled) {
    return { success: false, target, result: { shares: [], users: [] }, error: 'WSL required for SMB enumeration' };
  }

  const enumResult: SmbEnumResult = { shares: [], users: [] };

  // Try smbclient for share enumeration
  const smbAvailable = await checkWSLCommandExists('smbclient');
  if (smbAvailable) {
    const authArgs = username
      ? ['-U', `${username}%${password}`]
      : ['-N'];
    const smbResult = await executeWSL('smbclient', ['-L', target, ...authArgs], { timeout });
    if (smbResult.stdout) {
      enumResult.shares = parseSmbShares(smbResult.stdout);
    }
  }

  // Try enum4linux for deeper enumeration
  const enum4Available = await checkWSLCommandExists('enum4linux');
  if (enum4Available) {
    const args = username
      ? ['-u', username, '-p', password, '-a', target]
      : ['-a', target];
    const enumRes = await executeWSL('enum4linux', args, { timeout });
    if (enumRes.stdout) {
      const parsed = parseEnum4linux(enumRes.stdout);
      enumResult.users = parsed.users;
      enumResult.osInfo = parsed.osInfo;
      enumResult.workgroup = parsed.workgroup;
      if (enumResult.shares.length === 0) {
        enumResult.shares = parsed.shares;
      }
    }
  }

  if (!smbAvailable && !enum4Available) {
    return {
      success: false,
      target,
      result: enumResult,
      error: 'Neither smbclient nor enum4linux found in WSL'
    };
  }

  return { success: true, target, result: enumResult };
}

function parseSmbShares(output: string): SmbShare[] {
  const shares: SmbShare[] = [];
  const lines = output.split('\n');

  for (const line of lines) {
    const match = line.match(/^\s+(\S+)\s+(Disk|IPC|Printer)\s*(.*)/);
    if (match) {
      shares.push({
        name: match[1],
        type: match[2],
        comment: match[3]?.trim() || undefined
      });
    }
  }

  return shares;
}

function parseEnum4linux(output: string): { users: string[]; shares: SmbShare[]; osInfo?: string; workgroup?: string } {
  const users: string[] = [];
  const shares: SmbShare[] = [];
  let osInfo: string | undefined;
  let workgroup: string | undefined;

  const lines = output.split('\n');
  for (const line of lines) {
    // Users
    const userMatch = line.match(/user:\[([^\]]+)\]/);
    if (userMatch) {
      users.push(userMatch[1]);
    }

    // OS Info
    const osMatch = line.match(/OS=\[([^\]]+)\]/);
    if (osMatch) {
      osInfo = osMatch[1];
    }

    // Workgroup
    const wgMatch = line.match(/Domain=\[([^\]]+)\]/);
    if (wgMatch) {
      workgroup = wgMatch[1];
    }

    // Shares
    const shareMatch = line.match(/^\s+(\S+)\s+(Disk|IPC|Printer)\s*(.*)/);
    if (shareMatch) {
      shares.push({
        name: shareMatch[1],
        type: shareMatch[2],
        comment: shareMatch[3]?.trim() || undefined
      });
    }
  }

  return { users, shares, osInfo, workgroup };
}
