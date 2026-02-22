import { z } from 'zod';
import { isInScope } from '../../config.js';

export const reverseDnsSchema = z.object({
  ip: z.string().describe('IP address for reverse DNS lookup'),
  timeout: z.number().default(10000).describe('Timeout in milliseconds')
});

export type ReverseDnsInput = z.infer<typeof reverseDnsSchema>;

export async function reverseDnsLookup(input: ReverseDnsInput): Promise<{
  success: boolean;
  ip: string;
  hostname: string | null;
  allPtrRecords: string[];
  error?: string;
}> {
  const { ip, timeout } = input;

  if (!isInScope(ip)) {
    return {
      success: false,
      ip,
      hostname: null,
      allPtrRecords: [],
      error: `IP ${ip} is not in scope. Use vanguard_set_scope first.`
    };
  }

  // Validate IP format
  const ipv4Match = ip.match(/^(\d+)\.(\d+)\.(\d+)\.(\d+)$/);
  if (!ipv4Match) {
    return {
      success: false,
      ip,
      hostname: null,
      allPtrRecords: [],
      error: 'Invalid IPv4 address format'
    };
  }

  const parts = ip.split('.').reverse();
  const ptrDomain = `${parts.join('.')}.in-addr.arpa`;

  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeout);

    const url = `https://dns.google/resolve?name=${encodeURIComponent(ptrDomain)}&type=PTR`;
    const response = await fetch(url, {
      headers: { 'User-Agent': 'mcp-vanguard/2.0' },
      signal: controller.signal
    });
    clearTimeout(timer);

    if (!response.ok) {
      return { success: false, ip, hostname: null, allPtrRecords: [], error: `DNS query failed: ${response.status}` };
    }

    const data = await response.json() as {
      Status: number;
      Answer?: Array<{ data: string }>;
    };

    if (data.Status === 0 && data.Answer && data.Answer.length > 0) {
      const ptrs = data.Answer.map(a => a.data.replace(/\.$/, ''));
      return {
        success: true,
        ip,
        hostname: ptrs[0],
        allPtrRecords: ptrs
      };
    }

    return { success: true, ip, hostname: null, allPtrRecords: [], error: 'No PTR record found' };
  } catch (err) {
    return {
      success: false,
      ip,
      hostname: null,
      allPtrRecords: [],
      error: err instanceof Error ? err.message : 'Request failed'
    };
  }
}
