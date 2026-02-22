import { z } from 'zod';

export const networkCidrSchema = z.object({
  input: z.string().describe('CIDR notation (e.g., "192.168.1.0/24") or IP range'),
  operation: z.enum(['info', 'expand', 'contains']).default('info')
    .describe('Operation: info (subnet details), expand (list all IPs), contains (check if IP in range)'),
  checkIp: z.string().optional().describe('IP to check when operation is "contains"')
});

export type NetworkCidrInput = z.infer<typeof networkCidrSchema>;

interface SubnetInfo {
  network: string;
  broadcast: string;
  firstHost: string;
  lastHost: string;
  netmask: string;
  wildcardMask: string;
  prefix: number;
  totalHosts: number;
  usableHosts: number;
  ipClass: string;
  isPrivate: boolean;
}

export async function networkCidr(input: NetworkCidrInput): Promise<{
  success: boolean;
  operation: string;
  subnetInfo?: SubnetInfo;
  ipList?: string[];
  contains?: boolean;
  error?: string;
}> {
  const { input: cidrInput, operation, checkIp } = input;

  const parsed = parseCidr(cidrInput);
  if (!parsed) {
    return { success: false, operation, error: `Invalid CIDR notation: ${cidrInput}` };
  }

  const { ip, prefix } = parsed;
  const ipNum = ipToNumber(ip);
  const mask = prefix === 0 ? 0 : (~0 << (32 - prefix)) >>> 0;
  const network = (ipNum & mask) >>> 0;
  const broadcast = (network | ~mask) >>> 0;

  if (operation === 'info') {
    const totalHosts = Math.pow(2, 32 - prefix);
    const usableHosts = prefix <= 30 ? totalHosts - 2 : (prefix === 31 ? 2 : 1);

    return {
      success: true,
      operation,
      subnetInfo: {
        network: numberToIp(network),
        broadcast: numberToIp(broadcast),
        firstHost: numberToIp(network + 1),
        lastHost: numberToIp(broadcast - 1),
        netmask: numberToIp(mask),
        wildcardMask: numberToIp(~mask >>> 0),
        prefix,
        totalHosts,
        usableHosts,
        ipClass: getIpClass(network),
        isPrivate: isPrivateIp(network)
      }
    };
  }

  if (operation === 'expand') {
    const total = (broadcast - network) + 1;
    if (total > 1024) {
      return { success: false, operation, error: `Range too large (${total} IPs). Max 1024 (/22). Use info instead.` };
    }

    const ipList: string[] = [];
    for (let i = network; i <= broadcast; i++) {
      ipList.push(numberToIp(i));
    }

    return { success: true, operation, ipList };
  }

  if (operation === 'contains') {
    if (!checkIp) {
      return { success: false, operation, error: 'checkIp parameter required for contains operation' };
    }
    const checkNum = ipToNumber(checkIp);
    return { success: true, operation, contains: checkNum >= network && checkNum <= broadcast };
  }

  return { success: false, operation, error: `Unknown operation: ${operation}` };
}

function parseCidr(input: string): { ip: string; prefix: number } | null {
  const match = input.match(/^(\d+\.\d+\.\d+\.\d+)\/(\d+)$/);
  if (!match) return null;

  const prefix = parseInt(match[2], 10);
  if (prefix < 0 || prefix > 32) return null;

  return { ip: match[1], prefix };
}

function ipToNumber(ip: string): number {
  const parts = ip.split('.').map(Number);
  return ((parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]) >>> 0;
}

function numberToIp(num: number): string {
  return [
    (num >>> 24) & 0xFF,
    (num >>> 16) & 0xFF,
    (num >>> 8) & 0xFF,
    num & 0xFF
  ].join('.');
}

function getIpClass(ipNum: number): string {
  const first = (ipNum >>> 24) & 0xFF;
  if (first < 128) return 'A';
  if (first < 192) return 'B';
  if (first < 224) return 'C';
  if (first < 240) return 'D';
  return 'E';
}

function isPrivateIp(ipNum: number): boolean {
  const first = (ipNum >>> 24) & 0xFF;
  const second = (ipNum >>> 16) & 0xFF;

  // 10.0.0.0/8
  if (first === 10) return true;
  // 172.16.0.0/12
  if (first === 172 && second >= 16 && second <= 31) return true;
  // 192.168.0.0/16
  if (first === 192 && second === 168) return true;

  return false;
}
