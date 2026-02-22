import { z } from 'zod';
import { getConfig } from '../../config.js';

export const shodanSearchSchema = z.object({
  query: z.string().describe('Shodan search query (e.g., "apache port:8080 country:US") or IP address'),
  searchType: z.enum(['search', 'host']).default('search')
    .describe('search: query Shodan, host: lookup specific IP'),
  limit: z.number().default(20).describe('Maximum results (search only)'),
  timeout: z.number().default(15000).describe('Timeout in milliseconds')
});

export type ShodanSearchInput = z.infer<typeof shodanSearchSchema>;

interface ShodanHost {
  ip: string;
  ports: number[];
  hostnames: string[];
  os?: string;
  org?: string;
  isp?: string;
  country?: string;
  city?: string;
  vulns?: string[];
  services?: Array<{
    port: number;
    transport: string;
    product?: string;
    version?: string;
    banner?: string;
  }>;
}

export async function shodanSearch(input: ShodanSearchInput): Promise<{
  success: boolean;
  query: string;
  results: ShodanHost[];
  total?: number;
  error?: string;
}> {
  const { query, searchType, limit, timeout } = input;
  const config = getConfig();

  if (!config.apiKeys.shodan) {
    return {
      success: false,
      query,
      results: [],
      error: 'Shodan API key not configured. Add apiKeys.shodan to config.'
    };
  }

  try {
    if (searchType === 'host') {
      return await shodanHostLookup(query, config.apiKeys.shodan, timeout);
    }
    return await shodanQuery(query, config.apiKeys.shodan, limit, timeout);
  } catch (err) {
    return {
      success: false,
      query,
      results: [],
      error: err instanceof Error ? err.message : 'Shodan search failed'
    };
  }
}

async function shodanHostLookup(ip: string, apiKey: string, timeout: number): Promise<{
  success: boolean;
  query: string;
  results: ShodanHost[];
  error?: string;
}> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeout);

  const response = await fetch(
    `https://api.shodan.io/shodan/host/${encodeURIComponent(ip)}?key=${apiKey}`,
    {
      headers: { 'User-Agent': 'mcp-vanguard/2.0' },
      signal: controller.signal
    }
  );
  clearTimeout(timer);

  if (!response.ok) {
    return { success: false, query: ip, results: [], error: `Shodan API returned ${response.status}` };
  }

  const data = await response.json() as {
    ip_str: string;
    ports: number[];
    hostnames: string[];
    os?: string;
    org?: string;
    isp?: string;
    country_code?: string;
    city?: string;
    vulns?: string[];
    data?: Array<{
      port: number;
      transport: string;
      product?: string;
      version?: string;
      data?: string;
    }>;
  };

  return {
    success: true,
    query: ip,
    results: [{
      ip: data.ip_str,
      ports: data.ports || [],
      hostnames: data.hostnames || [],
      os: data.os,
      org: data.org,
      isp: data.isp,
      country: data.country_code,
      city: data.city,
      vulns: data.vulns?.slice(0, 20),
      services: data.data?.slice(0, 30).map(s => ({
        port: s.port,
        transport: s.transport,
        product: s.product,
        version: s.version,
        banner: s.data?.slice(0, 200)
      }))
    }]
  };
}

async function shodanQuery(query: string, apiKey: string, limit: number, timeout: number): Promise<{
  success: boolean;
  query: string;
  results: ShodanHost[];
  total?: number;
  error?: string;
}> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeout);

  const response = await fetch(
    `https://api.shodan.io/shodan/host/search?key=${apiKey}&query=${encodeURIComponent(query)}&page=1`,
    {
      headers: { 'User-Agent': 'mcp-vanguard/2.0' },
      signal: controller.signal
    }
  );
  clearTimeout(timer);

  if (!response.ok) {
    return { success: false, query, results: [], error: `Shodan API returned ${response.status}` };
  }

  const data = await response.json() as {
    total: number;
    matches: Array<{
      ip_str: string;
      port: number;
      transport: string;
      hostnames: string[];
      os?: string;
      org?: string;
      isp?: string;
      location?: { country_code?: string; city?: string };
      product?: string;
      version?: string;
      data?: string;
    }>;
  };

  // Group by IP
  const hostMap = new Map<string, ShodanHost>();
  for (const match of data.matches.slice(0, limit * 3)) {
    const existing = hostMap.get(match.ip_str);
    if (existing) {
      if (!existing.ports.includes(match.port)) existing.ports.push(match.port);
      existing.services?.push({
        port: match.port,
        transport: match.transport,
        product: match.product,
        version: match.version,
        banner: match.data?.slice(0, 200)
      });
    } else {
      hostMap.set(match.ip_str, {
        ip: match.ip_str,
        ports: [match.port],
        hostnames: match.hostnames || [],
        os: match.os,
        org: match.org,
        isp: match.isp,
        country: match.location?.country_code,
        city: match.location?.city,
        services: [{
          port: match.port,
          transport: match.transport,
          product: match.product,
          version: match.version,
          banner: match.data?.slice(0, 200)
        }]
      });
    }
  }

  return {
    success: true,
    query,
    results: [...hostMap.values()].slice(0, limit),
    total: data.total
  };
}
