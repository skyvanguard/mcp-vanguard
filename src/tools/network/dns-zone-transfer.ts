import { z } from 'zod';
import { isInScope, getConfig } from '../../config.js';
import { executeWSL, checkWSLCommandExists } from '../../executor/wsl.js';
import { executeWindows, checkCommandExists } from '../../executor/windows.js';

export const dnsZoneTransferSchema = z.object({
  domain: z.string().describe('Target domain to attempt zone transfer'),
  nameserver: z.string().optional().describe('Specific nameserver to query (auto-detected if empty)'),
  timeout: z.number().default(30000).describe('Timeout in milliseconds')
});

export type DnsZoneTransferInput = z.infer<typeof dnsZoneTransferSchema>;

interface ZoneRecord {
  name: string;
  ttl?: number;
  class: string;
  type: string;
  data: string;
}

export async function dnsZoneTransfer(input: DnsZoneTransferInput): Promise<{
  success: boolean;
  domain: string;
  transferSucceeded: boolean;
  records: ZoneRecord[];
  nameserversTested: string[];
  error?: string;
}> {
  const { domain, nameserver, timeout } = input;

  if (!isInScope(domain)) {
    return {
      success: false,
      domain,
      transferSucceeded: false,
      records: [],
      nameserversTested: [],
      error: `Domain ${domain} is not in scope. Use vanguard_set_scope first.`
    };
  }

  // Get nameservers to test
  const nameservers = nameserver ? [nameserver] : await getNS(domain, timeout);
  if (nameservers.length === 0) {
    return {
      success: false,
      domain,
      transferSucceeded: false,
      records: [],
      nameserversTested: [],
      error: 'Could not find nameservers for domain'
    };
  }

  const config = getConfig();

  for (const ns of nameservers) {
    // Try dig in WSL
    if (config.wslEnabled) {
      const digAvailable = await checkWSLCommandExists('dig');
      if (digAvailable) {
        const result = await executeWSL('dig', ['AXFR', domain, `@${ns}`], { timeout });
        if (result.stdout && !result.stdout.includes('Transfer failed') && !result.stdout.includes('; Transfer failed')) {
          const records = parseDigAxfr(result.stdout);
          if (records.length > 0) {
            return { success: true, domain, transferSucceeded: true, records, nameserversTested: nameservers };
          }
        }
      }
    }

    // Try nslookup on Windows (limited AXFR support)
    const nslookupAvailable = await checkCommandExists('nslookup');
    if (nslookupAvailable) {
      const result = await executeWindows('nslookup', ['-type=AXFR', domain, ns], { timeout });
      if (result.stdout && !result.stdout.includes('refused')) {
        const records = parseNslookupAxfr(result.stdout);
        if (records.length > 0) {
          return { success: true, domain, transferSucceeded: true, records, nameserversTested: nameservers };
        }
      }
    }
  }

  return {
    success: true,
    domain,
    transferSucceeded: false,
    records: [],
    nameserversTested: nameservers,
    error: 'Zone transfer denied by all nameservers (this is expected for properly configured DNS)'
  };
}

async function getNS(domain: string, timeout: number): Promise<string[]> {
  try {
    const url = `https://dns.google/resolve?name=${encodeURIComponent(domain)}&type=NS`;
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeout);

    const response = await fetch(url, {
      headers: { 'User-Agent': 'mcp-vanguard/2.0' },
      signal: controller.signal
    });
    clearTimeout(timer);

    if (!response.ok) return [];

    const data = await response.json() as {
      Status: number;
      Answer?: Array<{ data: string }>;
    };

    return (data.Answer || []).map(a => a.data.replace(/\.$/, ''));
  } catch {
    return [];
  }
}

function parseDigAxfr(output: string): ZoneRecord[] {
  const records: ZoneRecord[] = [];
  const lines = output.split('\n');

  for (const line of lines) {
    if (line.startsWith(';') || line.trim() === '') continue;
    const match = line.match(/^(\S+)\s+(\d+)?\s*(IN|CH|HS)\s+(\S+)\s+(.+)$/);
    if (match) {
      records.push({
        name: match[1],
        ttl: match[2] ? parseInt(match[2], 10) : undefined,
        class: match[3],
        type: match[4],
        data: match[5].trim()
      });
    }
  }

  return records;
}

function parseNslookupAxfr(output: string): ZoneRecord[] {
  const records: ZoneRecord[] = [];
  const lines = output.split('\n');

  for (const line of lines) {
    const match = line.match(/(\S+)\s+(?:internet\s+address|MX|NS|TXT|CNAME|AAAA|SOA)\s*=?\s*(.+)/i);
    if (match) {
      records.push({
        name: match[1],
        class: 'IN',
        type: 'A',
        data: match[2].trim()
      });
    }
  }

  return records;
}
