import { z } from 'zod';
import { getConfig } from '../../config.js';

export const dnsHistorySchema = z.object({
  domain: z.string().describe('Domain to lookup DNS history'),
  recordType: z.enum(['a', 'aaaa', 'mx', 'ns', 'txt']).default('a')
    .describe('DNS record type to check history'),
  timeout: z.number().default(15000).describe('Timeout in milliseconds')
});

export type DnsHistoryInput = z.infer<typeof dnsHistorySchema>;

interface DnsHistoryEntry {
  ip?: string;
  value?: string;
  firstSeen?: string;
  lastSeen?: string;
  organization?: string;
}

export async function dnsHistory(input: DnsHistoryInput): Promise<{
  success: boolean;
  domain: string;
  recordType: string;
  history: DnsHistoryEntry[];
  error?: string;
}> {
  const { domain, recordType, timeout } = input;
  const config = getConfig();

  // Try SecurityTrails if key available
  if (config.apiKeys.securitytrails) {
    try {
      return await securityTrailsHistory(domain, recordType, config.apiKeys.securitytrails, timeout);
    } catch {
      // Fall through to free method
    }
  }

  // Free fallback: use ViewDNS.info API
  try {
    return await viewDnsHistory(domain, recordType, timeout);
  } catch (err) {
    return {
      success: false,
      domain,
      recordType,
      history: [],
      error: err instanceof Error ? err.message : 'DNS history lookup failed'
    };
  }
}

async function securityTrailsHistory(
  domain: string,
  recordType: string,
  apiKey: string,
  timeout: number
): Promise<{
  success: boolean;
  domain: string;
  recordType: string;
  history: DnsHistoryEntry[];
  error?: string;
}> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeout);

  const response = await fetch(
    `https://api.securitytrails.com/v1/history/${encodeURIComponent(domain)}/dns/${recordType}`,
    {
      headers: {
        'APIKEY': apiKey,
        'Accept': 'application/json',
        'User-Agent': 'mcp-vanguard/2.0'
      },
      signal: controller.signal
    }
  );
  clearTimeout(timer);

  if (!response.ok) {
    throw new Error(`SecurityTrails returned ${response.status}`);
  }

  const data = await response.json() as {
    records?: Array<{
      values?: Array<{
        ip?: string;
        ip_count?: number;
      }>;
      organizations?: string[];
      first_seen?: string;
      last_seen?: string;
      type?: string;
    }>;
  };

  const history: DnsHistoryEntry[] = (data.records || []).map(r => ({
    ip: r.values?.[0]?.ip,
    firstSeen: r.first_seen,
    lastSeen: r.last_seen,
    organization: r.organizations?.[0]
  }));

  return { success: true, domain, recordType, history };
}

async function viewDnsHistory(
  domain: string,
  recordType: string,
  timeout: number
): Promise<{
  success: boolean;
  domain: string;
  recordType: string;
  history: DnsHistoryEntry[];
  error?: string;
}> {
  // ViewDNS.info free IP history
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeout);

  const response = await fetch(
    `https://viewdns.info/iphistory/?domain=${encodeURIComponent(domain)}&output=json`,
    {
      headers: {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
      },
      signal: controller.signal
    }
  );
  clearTimeout(timer);

  if (!response.ok) {
    return {
      success: false,
      domain,
      recordType,
      history: [],
      error: `ViewDNS returned ${response.status}. Add apiKeys.securitytrails for full DNS history.`
    };
  }

  try {
    const data = await response.json() as {
      response?: {
        records?: Array<{
          ip: string;
          lastseen: string;
          organization: string;
        }>;
      };
    };

    const history: DnsHistoryEntry[] = (data.response?.records || []).map(r => ({
      ip: r.ip,
      lastSeen: r.lastseen,
      organization: r.organization
    }));

    return { success: true, domain, recordType, history };
  } catch {
    return {
      success: false,
      domain,
      recordType,
      history: [],
      error: 'Could not parse ViewDNS response. Add apiKeys.securitytrails for reliable DNS history.'
    };
  }
}
