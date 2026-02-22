import { z } from 'zod';
import { getConfig } from '../../config.js';

export const breachCheckSchema = z.object({
  query: z.string().describe('Email address or domain to check for breaches'),
  queryType: z.enum(['email', 'domain']).default('email')
    .describe('Type of query'),
  timeout: z.number().default(10000).describe('Timeout in milliseconds')
});

export type BreachCheckInput = z.infer<typeof breachCheckSchema>;

interface Breach {
  name: string;
  domain?: string;
  breachDate?: string;
  addedDate?: string;
  pwnCount?: number;
  description?: string;
  dataClasses?: string[];
  isVerified?: boolean;
}

export async function breachCheck(input: BreachCheckInput): Promise<{
  success: boolean;
  query: string;
  breaches: Breach[];
  totalBreaches: number;
  totalExposedRecords: number;
  error?: string;
}> {
  const { query, queryType, timeout } = input;
  const config = getConfig();

  // Try HIBP API if key available
  if (config.apiKeys.haveibeenpwned) {
    try {
      const result = await checkHIBP(query, queryType, config.apiKeys.haveibeenpwned, timeout);
      return result;
    } catch {
      // Fall through to free alternative
    }
  }

  // Free alternative: check via breach directory APIs
  try {
    return await checkBreachDirectory(query, queryType, timeout);
  } catch (err) {
    return {
      success: false,
      query,
      breaches: [],
      totalBreaches: 0,
      totalExposedRecords: 0,
      error: err instanceof Error ? err.message : 'Breach check failed'
    };
  }
}

async function checkHIBP(
  query: string,
  queryType: string,
  apiKey: string,
  timeout: number
): Promise<{
  success: boolean;
  query: string;
  breaches: Breach[];
  totalBreaches: number;
  totalExposedRecords: number;
}> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeout);

  const endpoint = queryType === 'email'
    ? `https://haveibeenpwned.com/api/v3/breachedaccount/${encodeURIComponent(query)}`
    : `https://haveibeenpwned.com/api/v3/breaches?domain=${encodeURIComponent(query)}`;

  const response = await fetch(endpoint, {
    headers: {
      'hibp-api-key': apiKey,
      'User-Agent': 'mcp-vanguard/2.0'
    },
    signal: controller.signal
  });
  clearTimeout(timer);

  if (response.status === 404) {
    return { success: true, query, breaches: [], totalBreaches: 0, totalExposedRecords: 0 };
  }

  if (!response.ok) {
    throw new Error(`HIBP returned ${response.status}`);
  }

  const data = await response.json() as Array<{
    Name: string;
    Domain: string;
    BreachDate: string;
    AddedDate: string;
    PwnCount: number;
    Description: string;
    DataClasses: string[];
    IsVerified: boolean;
  }>;

  const breaches: Breach[] = data.map(b => ({
    name: b.Name,
    domain: b.Domain,
    breachDate: b.BreachDate,
    addedDate: b.AddedDate,
    pwnCount: b.PwnCount,
    description: b.Description?.replace(/<[^>]+>/g, '').slice(0, 300),
    dataClasses: b.DataClasses,
    isVerified: b.IsVerified
  }));

  const totalExposed = breaches.reduce((sum, b) => sum + (b.pwnCount || 0), 0);

  return {
    success: true,
    query,
    breaches,
    totalBreaches: breaches.length,
    totalExposedRecords: totalExposed
  };
}

async function checkBreachDirectory(
  query: string,
  queryType: string,
  timeout: number
): Promise<{
  success: boolean;
  query: string;
  breaches: Breach[];
  totalBreaches: number;
  totalExposedRecords: number;
  error?: string;
}> {
  // Use the free breach compilation database
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeout);

  try {
    const response = await fetch(
      `https://haveibeenpwned.com/api/v3/breaches`,
      {
        headers: { 'User-Agent': 'mcp-vanguard/2.0' },
        signal: controller.signal
      }
    );
    clearTimeout(timer);

    if (!response.ok) {
      return {
        success: false,
        query,
        breaches: [],
        totalBreaches: 0,
        totalExposedRecords: 0,
        error: 'No HIBP API key. Add apiKeys.haveibeenpwned for email/domain breach checks. Showing known breaches list.'
      };
    }

    const allBreaches = await response.json() as Array<{
      Name: string;
      Domain: string;
      BreachDate: string;
      PwnCount: number;
      DataClasses: string[];
      IsVerified: boolean;
    }>;

    // Filter by domain if applicable
    let filtered = allBreaches;
    if (queryType === 'domain') {
      const domain = query.toLowerCase();
      filtered = allBreaches.filter(b =>
        b.Domain?.toLowerCase() === domain ||
        b.Domain?.toLowerCase().endsWith(`.${domain}`)
      );
    }

    const breaches: Breach[] = filtered.slice(0, 50).map(b => ({
      name: b.Name,
      domain: b.Domain,
      breachDate: b.BreachDate,
      pwnCount: b.PwnCount,
      dataClasses: b.DataClasses,
      isVerified: b.IsVerified
    }));

    return {
      success: true,
      query,
      breaches,
      totalBreaches: breaches.length,
      totalExposedRecords: breaches.reduce((sum, b) => sum + (b.pwnCount || 0), 0),
      error: queryType === 'email' ? 'HIBP API key required for email breach checks. Showing domain breaches only.' : undefined
    };
  } catch {
    return {
      success: false,
      query,
      breaches: [],
      totalBreaches: 0,
      totalExposedRecords: 0,
      error: 'No HIBP API key configured and fallback failed. Add apiKeys.haveibeenpwned to config.'
    };
  }
}
