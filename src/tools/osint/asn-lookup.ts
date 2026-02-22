import { z } from 'zod';

export const asnLookupSchema = z.object({
  query: z.string().describe('ASN number (e.g., "AS13335"), IP address, or organization name'),
  timeout: z.number().default(10000).describe('Timeout in milliseconds')
});

export type AsnLookupInput = z.infer<typeof asnLookupSchema>;

interface AsnResult {
  asn: string;
  name?: string;
  description?: string;
  country?: string;
  prefixes?: string[];
  peers?: string[];
}

export async function asnLookup(input: AsnLookupInput): Promise<{
  success: boolean;
  query: string;
  results: AsnResult[];
  error?: string;
}> {
  const { query, timeout } = input;

  try {
    // Detect query type
    const isAsn = /^AS?\d+$/i.test(query);
    const isIp = /^\d+\.\d+\.\d+\.\d+$/.test(query);

    if (isIp) {
      return await lookupByIp(query, timeout);
    }

    if (isAsn) {
      const asnNum = query.replace(/^AS/i, '');
      return await lookupByAsn(asnNum, query, timeout);
    }

    // Search by name
    return await searchByName(query, timeout);
  } catch (err) {
    return {
      success: false,
      query,
      results: [],
      error: err instanceof Error ? err.message : 'ASN lookup failed'
    };
  }
}

async function lookupByIp(ip: string, timeout: number): Promise<{
  success: boolean;
  query: string;
  results: AsnResult[];
  error?: string;
}> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeout);

  const response = await fetch(`https://api.bgpview.io/ip/${encodeURIComponent(ip)}`, {
    headers: { 'User-Agent': 'mcp-vanguard/2.0' },
    signal: controller.signal
  });
  clearTimeout(timer);

  if (!response.ok) {
    return { success: false, query: ip, results: [], error: `API returned ${response.status}` };
  }

  const data = await response.json() as {
    status: string;
    data: {
      prefixes?: Array<{
        asn: { asn: number; name: string; description: string; country_code: string };
        prefix: string;
      }>;
    };
  };

  if (data.status !== 'ok' || !data.data.prefixes?.length) {
    return { success: true, query: ip, results: [], error: 'No ASN data found for IP' };
  }

  const results: AsnResult[] = data.data.prefixes.map(p => ({
    asn: `AS${p.asn.asn}`,
    name: p.asn.name,
    description: p.asn.description,
    country: p.asn.country_code,
    prefixes: [p.prefix]
  }));

  return { success: true, query: ip, results };
}

async function lookupByAsn(asnNum: string, query: string, timeout: number): Promise<{
  success: boolean;
  query: string;
  results: AsnResult[];
  error?: string;
}> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeout);

  const response = await fetch(`https://api.bgpview.io/asn/${asnNum}`, {
    headers: { 'User-Agent': 'mcp-vanguard/2.0' },
    signal: controller.signal
  });
  clearTimeout(timer);

  if (!response.ok) {
    return { success: false, query, results: [], error: `API returned ${response.status}` };
  }

  const data = await response.json() as {
    status: string;
    data: {
      asn: number;
      name: string;
      description_short: string;
      country_code: string;
    };
  };

  // Also get prefixes
  const prefixResponse = await fetch(`https://api.bgpview.io/asn/${asnNum}/prefixes`, {
    headers: { 'User-Agent': 'mcp-vanguard/2.0' }
  });

  let prefixes: string[] = [];
  if (prefixResponse.ok) {
    const prefixData = await prefixResponse.json() as {
      data: {
        ipv4_prefixes?: Array<{ prefix: string }>;
      };
    };
    prefixes = (prefixData.data.ipv4_prefixes || []).map(p => p.prefix).slice(0, 50);
  }

  return {
    success: true,
    query,
    results: [{
      asn: `AS${data.data.asn}`,
      name: data.data.name,
      description: data.data.description_short,
      country: data.data.country_code,
      prefixes
    }]
  };
}

async function searchByName(name: string, timeout: number): Promise<{
  success: boolean;
  query: string;
  results: AsnResult[];
  error?: string;
}> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeout);

  const response = await fetch(`https://api.bgpview.io/search?query_term=${encodeURIComponent(name)}`, {
    headers: { 'User-Agent': 'mcp-vanguard/2.0' },
    signal: controller.signal
  });
  clearTimeout(timer);

  if (!response.ok) {
    return { success: false, query: name, results: [], error: `API returned ${response.status}` };
  }

  const data = await response.json() as {
    status: string;
    data: {
      asns?: Array<{
        asn: number;
        name: string;
        description: string;
        country_code: string;
      }>;
    };
  };

  const results: AsnResult[] = (data.data.asns || []).slice(0, 20).map(a => ({
    asn: `AS${a.asn}`,
    name: a.name,
    description: a.description,
    country: a.country_code
  }));

  return { success: true, query: name, results };
}
