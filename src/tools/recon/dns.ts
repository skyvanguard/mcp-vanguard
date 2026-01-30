import { z } from 'zod';

export const dnsRecordsSchema = z.object({
  domain: z.string().describe('Domain to query DNS records'),
  recordTypes: z.array(z.enum(['A', 'AAAA', 'CNAME', 'MX', 'NS', 'TXT', 'SOA', 'PTR']))
    .default(['A', 'AAAA', 'CNAME', 'MX', 'NS', 'TXT'])
    .describe('DNS record types to query')
});

export type DnsRecordsInput = z.infer<typeof dnsRecordsSchema>;

interface DnsRecord {
  type: string;
  name: string;
  data: string;
  ttl?: number;
}

export async function dnsRecords(input: DnsRecordsInput): Promise<{
  success: boolean;
  domain: string;
  records: DnsRecord[];
  error?: string;
}> {
  const { domain, recordTypes } = input;

  const records: DnsRecord[] = [];
  const errors: string[] = [];

  for (const recordType of recordTypes) {
    try {
      const result = await queryDns(domain, recordType);
      records.push(...result);
    } catch (err) {
      errors.push(`${recordType}: ${err instanceof Error ? err.message : 'failed'}`);
    }
  }

  return {
    success: records.length > 0,
    domain,
    records,
    error: errors.length > 0 ? errors.join('; ') : undefined
  };
}

async function queryDns(domain: string, type: string): Promise<DnsRecord[]> {
  const url = `https://dns.google/resolve?name=${encodeURIComponent(domain)}&type=${type}`;

  const response = await fetch(url, {
    headers: {
      'User-Agent': 'mcp-vanguard/1.0'
    }
  });

  if (!response.ok) {
    throw new Error(`DNS query failed: ${response.status}`);
  }

  const data = await response.json() as {
    Status: number;
    Answer?: Array<{
      name: string;
      type: number;
      TTL: number;
      data: string;
    }>;
    Authority?: Array<{
      name: string;
      type: number;
      TTL: number;
      data: string;
    }>;
  };

  if (data.Status !== 0 && data.Status !== 3) {
    throw new Error(`DNS query returned status ${data.Status}`);
  }

  const records: DnsRecord[] = [];

  const dnsTypeMap: Record<number, string> = {
    1: 'A',
    2: 'NS',
    5: 'CNAME',
    6: 'SOA',
    12: 'PTR',
    15: 'MX',
    16: 'TXT',
    28: 'AAAA'
  };

  if (data.Answer) {
    for (const answer of data.Answer) {
      records.push({
        type: dnsTypeMap[answer.type] || `TYPE${answer.type}`,
        name: answer.name,
        data: answer.data,
        ttl: answer.TTL
      });
    }
  }

  return records;
}

export async function reverseDns(ip: string): Promise<{
  success: boolean;
  ip: string;
  hostname?: string;
  error?: string;
}> {
  const parts = ip.split('.').reverse();
  const ptrDomain = `${parts.join('.')}.in-addr.arpa`;

  const url = `https://dns.google/resolve?name=${encodeURIComponent(ptrDomain)}&type=PTR`;

  try {
    const response = await fetch(url, {
      headers: {
        'User-Agent': 'mcp-vanguard/1.0'
      }
    });

    if (!response.ok) {
      return {
        success: false,
        ip,
        error: `DNS query failed: ${response.status}`
      };
    }

    const data = await response.json() as {
      Status: number;
      Answer?: Array<{ data: string }>;
    };

    if (data.Status === 0 && data.Answer && data.Answer.length > 0) {
      return {
        success: true,
        ip,
        hostname: data.Answer[0].data.replace(/\.$/, '')
      };
    }

    return {
      success: false,
      ip,
      error: 'No PTR record found'
    };
  } catch (err) {
    return {
      success: false,
      ip,
      error: err instanceof Error ? err.message : 'Request failed'
    };
  }
}
