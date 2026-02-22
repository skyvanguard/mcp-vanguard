import { z } from 'zod';
import { getConfig } from '../../config.js';

export const domainReputationSchema = z.object({
  domain: z.string().describe('Domain to check reputation'),
  timeout: z.number().default(15000).describe('Timeout in milliseconds')
});

export type DomainReputationInput = z.infer<typeof domainReputationSchema>;

interface ReputationSource {
  source: string;
  score?: number;
  category?: string;
  malicious: boolean;
  details?: string;
}

export async function domainReputation(input: DomainReputationInput): Promise<{
  success: boolean;
  domain: string;
  overallRisk: 'low' | 'medium' | 'high' | 'critical' | 'unknown';
  sources: ReputationSource[];
  error?: string;
}> {
  const { domain, timeout } = input;
  const config = getConfig();
  const sources: ReputationSource[] = [];

  // VirusTotal
  if (config.apiKeys.virustotal) {
    try {
      const vtResult = await checkVirusTotal(domain, config.apiKeys.virustotal, timeout);
      sources.push(vtResult);
    } catch {
      sources.push({ source: 'virustotal', malicious: false, details: 'API error' });
    }
  }

  // AbuseIPDB (for IPs, but also useful for domains)
  if (config.apiKeys.abuseipdb) {
    try {
      const abuseResult = await checkAbuseIPDB(domain, config.apiKeys.abuseipdb, timeout);
      sources.push(abuseResult);
    } catch {
      sources.push({ source: 'abuseipdb', malicious: false, details: 'API error' });
    }
  }

  // Google Safe Browsing (free, no key needed, via transparency report)
  try {
    const gsb = await checkGoogleSafeBrowsing(domain, timeout);
    sources.push(gsb);
  } catch {
    sources.push({ source: 'google_safe_browsing', malicious: false, details: 'Check failed' });
  }

  // Determine overall risk
  const maliciousCount = sources.filter(s => s.malicious).length;
  let overallRisk: 'low' | 'medium' | 'high' | 'critical' | 'unknown' = 'unknown';
  if (sources.length > 0) {
    if (maliciousCount === 0) overallRisk = 'low';
    else if (maliciousCount === 1) overallRisk = 'medium';
    else if (maliciousCount === 2) overallRisk = 'high';
    else overallRisk = 'critical';
  }

  return {
    success: true,
    domain,
    overallRisk,
    sources,
    error: sources.length === 0 ? 'No API keys configured. Add virustotal or abuseipdb keys.' : undefined
  };
}

async function checkVirusTotal(domain: string, apiKey: string, timeout: number): Promise<ReputationSource> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeout);

  const response = await fetch(`https://www.virustotal.com/api/v3/domains/${encodeURIComponent(domain)}`, {
    headers: {
      'x-apikey': apiKey,
      'User-Agent': 'mcp-vanguard/2.0'
    },
    signal: controller.signal
  });
  clearTimeout(timer);

  if (!response.ok) {
    return { source: 'virustotal', malicious: false, details: `HTTP ${response.status}` };
  }

  const data = await response.json() as {
    data: {
      attributes: {
        last_analysis_stats?: {
          malicious: number;
          suspicious: number;
          harmless: number;
          undetected: number;
        };
        reputation?: number;
        categories?: Record<string, string>;
      };
    };
  };

  const stats = data.data.attributes.last_analysis_stats;
  const maliciousCount = (stats?.malicious || 0) + (stats?.suspicious || 0);
  const categories = data.data.attributes.categories;
  const categoryStr = categories ? Object.values(categories).join(', ') : undefined;

  return {
    source: 'virustotal',
    score: data.data.attributes.reputation,
    category: categoryStr,
    malicious: maliciousCount > 2,
    details: stats ? `${maliciousCount} engines flagged (${stats.harmless} clean)` : undefined
  };
}

async function checkAbuseIPDB(target: string, apiKey: string, timeout: number): Promise<ReputationSource> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeout);

  const response = await fetch(`https://api.abuseipdb.com/api/v2/check?ipAddress=${encodeURIComponent(target)}`, {
    headers: {
      'Key': apiKey,
      'Accept': 'application/json',
      'User-Agent': 'mcp-vanguard/2.0'
    },
    signal: controller.signal
  });
  clearTimeout(timer);

  if (!response.ok) {
    return { source: 'abuseipdb', malicious: false, details: `HTTP ${response.status}` };
  }

  const data = await response.json() as {
    data: {
      abuseConfidenceScore: number;
      totalReports: number;
      isp?: string;
      countryCode?: string;
    };
  };

  return {
    source: 'abuseipdb',
    score: data.data.abuseConfidenceScore,
    malicious: data.data.abuseConfidenceScore > 50,
    details: `Score: ${data.data.abuseConfidenceScore}%, Reports: ${data.data.totalReports}`
  };
}

async function checkGoogleSafeBrowsing(domain: string, timeout: number): Promise<ReputationSource> {
  // Use the transparency report URL as a lightweight check
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeout);

  const response = await fetch(
    `https://transparencyreport.google.com/transparencyreport/api/v3/safebrowsing/status?site=${encodeURIComponent(domain)}`,
    {
      headers: { 'User-Agent': 'mcp-vanguard/2.0' },
      signal: controller.signal
    }
  );
  clearTimeout(timer);

  if (!response.ok) {
    return { source: 'google_safe_browsing', malicious: false, details: 'Unable to check' };
  }

  const text = await response.text();
  // Google returns unsafe sites with specific status codes in the response
  const isMalicious = text.includes('"2"') || text.includes('"3"') || text.includes('"4"');

  return {
    source: 'google_safe_browsing',
    malicious: isMalicious,
    details: isMalicious ? 'Flagged as unsafe by Google' : 'No issues found'
  };
}
