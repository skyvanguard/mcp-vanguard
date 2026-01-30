import { z } from 'zod';
import { isInScope } from '../../config.js';

export const subdomainEnumSchema = z.object({
  domain: z.string().describe('Target domain to enumerate subdomains'),
  useCrtsh: z.boolean().default(true).describe('Use crt.sh certificate transparency'),
  useDnsBrute: z.boolean().default(false).describe('Use DNS bruteforce (slower)'),
  wordlist: z.string().optional().describe('Custom wordlist for DNS brute')
});

export type SubdomainEnumInput = z.infer<typeof subdomainEnumSchema>;

interface SubdomainResult {
  subdomain: string;
  source: string;
  resolved?: string;
}

export async function subdomainEnum(input: SubdomainEnumInput): Promise<{
  success: boolean;
  domain: string;
  subdomains: SubdomainResult[];
  error?: string;
}> {
  const { domain, useCrtsh, useDnsBrute } = input;

  if (!isInScope(domain)) {
    return {
      success: false,
      domain,
      subdomains: [],
      error: `Domain ${domain} is not in scope. Use vanguard_set_scope to add it.`
    };
  }

  const subdomains: SubdomainResult[] = [];

  if (useCrtsh) {
    try {
      const crtshResults = await queryCrtsh(domain);
      subdomains.push(...crtshResults.map(sub => ({
        subdomain: sub,
        source: 'crt.sh'
      })));
    } catch (err) {
      console.error('crt.sh query failed:', err);
    }
  }

  if (useDnsBrute) {
    const commonSubdomains = [
      'www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1', 'ns2',
      'ns3', 'ns4', 'blog', 'wiki', 'vpn', 'secure', 'server', 'dev', 'staging',
      'api', 'app', 'admin', 'portal', 'intranet', 'login', 'dashboard', 'cdn',
      'static', 'assets', 'images', 'media', 'files', 'backup', 'db', 'database',
      'mysql', 'postgres', 'redis', 'elastic', 'search', 'monitor', 'status',
      'test', 'demo', 'beta', 'alpha', 'stage', 'uat', 'qa', 'prod', 'production'
    ];

    for (const sub of commonSubdomains) {
      const fullDomain = `${sub}.${domain}`;
      const resolved = await resolveDomain(fullDomain);
      if (resolved) {
        const existing = subdomains.find(s => s.subdomain === fullDomain);
        if (existing) {
          existing.resolved = resolved;
        } else {
          subdomains.push({
            subdomain: fullDomain,
            source: 'dns_brute',
            resolved
          });
        }
      }
    }
  }

  const uniqueSubdomains = Array.from(
    new Map(subdomains.map(s => [s.subdomain, s])).values()
  );

  return {
    success: true,
    domain,
    subdomains: uniqueSubdomains.sort((a, b) =>
      a.subdomain.localeCompare(b.subdomain)
    )
  };
}

async function queryCrtsh(domain: string): Promise<string[]> {
  const url = `https://crt.sh/?q=%.${encodeURIComponent(domain)}&output=json`;

  const response = await fetch(url, {
    headers: {
      'User-Agent': 'mcp-vanguard/1.0'
    }
  });

  if (!response.ok) {
    throw new Error(`crt.sh returned ${response.status}`);
  }

  const data = await response.json() as Array<{ name_value: string }>;

  const subdomains = new Set<string>();
  for (const entry of data) {
    const names = entry.name_value.split('\n');
    for (const name of names) {
      const cleaned = name.toLowerCase().trim();
      if (cleaned.endsWith(domain) && !cleaned.startsWith('*')) {
        subdomains.add(cleaned);
      }
    }
  }

  return Array.from(subdomains);
}

async function resolveDomain(domain: string): Promise<string | null> {
  try {
    const url = `https://dns.google/resolve?name=${encodeURIComponent(domain)}&type=A`;
    const response = await fetch(url);

    if (!response.ok) {
      return null;
    }

    const data = await response.json() as {
      Status: number;
      Answer?: Array<{ data: string }>;
    };

    if (data.Status === 0 && data.Answer && data.Answer.length > 0) {
      return data.Answer[0].data;
    }

    return null;
  } catch {
    return null;
  }
}
