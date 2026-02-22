import { z } from 'zod';
import { isInScope } from '../../config.js';

export const subdomainTakeoverSchema = z.object({
  domain: z.string().describe('Domain to check subdomains for takeover potential'),
  subdomains: z.array(z.string()).optional()
    .describe('Specific subdomains to check (auto-generated common list if omitted)'),
  timeout: z.number().default(10000).describe('Per-request timeout in milliseconds'),
});

export type SubdomainTakeoverInput = z.infer<typeof subdomainTakeoverSchema>;

interface TakeoverResult {
  subdomain: string;
  cname?: string;
  service?: string;
  vulnerable: boolean;
  evidence?: string;
}

const TAKEOVER_FINGERPRINTS: Array<{ service: string; cnames: string[]; bodyPatterns: string[] }> = [
  { service: 'GitHub Pages', cnames: ['github.io'], bodyPatterns: ['There isn\'t a GitHub Pages site here', 'For root URLs'] },
  { service: 'Heroku', cnames: ['herokuapp.com', 'herokussl.com'], bodyPatterns: ['No such app', 'no-such-app'] },
  { service: 'AWS S3', cnames: ['s3.amazonaws.com', 's3-website'], bodyPatterns: ['NoSuchBucket', 'The specified bucket does not exist'] },
  { service: 'Shopify', cnames: ['myshopify.com'], bodyPatterns: ['Sorry, this shop is currently unavailable'] },
  { service: 'Tumblr', cnames: ['domains.tumblr.com'], bodyPatterns: ['There\'s nothing here', 'Whatever you were looking for'] },
  { service: 'WordPress.com', cnames: ['wordpress.com'], bodyPatterns: ['Do you want to register'] },
  { service: 'Surge.sh', cnames: ['surge.sh'], bodyPatterns: ['project not found'] },
  { service: 'Fastly', cnames: ['fastly.net'], bodyPatterns: ['Fastly error: unknown domain'] },
  { service: 'Pantheon', cnames: ['pantheonsite.io'], bodyPatterns: ['The gods are wise'] },
  { service: 'Zendesk', cnames: ['zendesk.com'], bodyPatterns: ['Help Center Closed'] },
  { service: 'Azure', cnames: ['azurewebsites.net', 'cloudapp.net', 'trafficmanager.net'], bodyPatterns: ['404 Web Site not found'] },
  { service: 'Unbounce', cnames: ['unbouncepages.com'], bodyPatterns: ['The requested URL was not found'] },
  { service: 'Cargo', cnames: ['cargocollective.com'], bodyPatterns: ['404 Not Found'] },
  { service: 'Fly.io', cnames: ['fly.dev'], bodyPatterns: ['404 Not Found'] },
];

const COMMON_SUBDOMAINS = [
  'blog', 'shop', 'store', 'mail', 'dev', 'staging', 'beta', 'app',
  'api', 'cdn', 'assets', 'media', 'static', 'docs', 'help', 'support',
  'status', 'admin', 'portal', 'dashboard', 'test', 'demo', 'preview',
];

export async function subdomainTakeover(input: SubdomainTakeoverInput): Promise<{
  success: boolean;
  domain: string;
  results: TakeoverResult[];
  vulnerable: boolean;
  error?: string;
}> {
  const { domain, subdomains, timeout } = input;

  if (!isInScope(domain)) {
    return { success: false, domain, results: [], vulnerable: false, error: `Target ${domain} is not in scope.` };
  }

  const subsToCheck = subdomains || COMMON_SUBDOMAINS.map(s => `${s}.${domain}`);
  const results: TakeoverResult[] = [];

  for (const sub of subsToCheck) {
    const fullDomain = sub.includes('.') ? sub : `${sub}.${domain}`;

    // Resolve CNAME
    let cname: string | undefined;
    try {
      const dnsResponse = await fetch(`https://dns.google/resolve?name=${fullDomain}&type=CNAME`, {
        headers: { 'Accept': 'application/dns-json' },
        signal: AbortSignal.timeout(5000),
      });
      const dnsData = await dnsResponse.json() as { Answer?: Array<{ data: string }> };
      cname = dnsData.Answer?.[0]?.data?.replace(/\.$/, '');
    } catch { /* DNS lookup failed */ }

    // Check if CNAME points to a takeover-eligible service
    let matchedService: string | undefined;
    let bodyPatterns: string[] = [];

    if (cname) {
      for (const fp of TAKEOVER_FINGERPRINTS) {
        if (fp.cnames.some(c => cname!.includes(c))) {
          matchedService = fp.service;
          bodyPatterns = fp.bodyPatterns;
          break;
        }
      }
    }

    // If CNAME matches a service, check if the response indicates takeover
    if (matchedService) {
      try {
        const controller = new AbortController();
        const timer = setTimeout(() => controller.abort(), timeout);

        const response = await fetch(`http://${fullDomain}`, {
          headers: { 'User-Agent': 'mcp-vanguard/2.0', 'Host': fullDomain },
          signal: controller.signal,
          redirect: 'follow',
        });
        clearTimeout(timer);

        const body = await response.text();
        const hasFingerprint = bodyPatterns.some(p => body.includes(p));

        results.push({
          subdomain: fullDomain,
          cname,
          service: matchedService,
          vulnerable: hasFingerprint,
          evidence: hasFingerprint ? `${matchedService} takeover fingerprint detected` : undefined,
        });
      } catch {
        // Connection refused/timeout might also indicate dangling CNAME
        results.push({
          subdomain: fullDomain,
          cname,
          service: matchedService,
          vulnerable: true,
          evidence: `CNAME to ${matchedService} but host unreachable (potential takeover)`,
        });
      }
    } else if (cname) {
      results.push({
        subdomain: fullDomain,
        cname,
        vulnerable: false,
      });
    }
    // Skip subdomains with no CNAME (not relevant for takeover)
  }

  return {
    success: true,
    domain,
    results,
    vulnerable: results.some(r => r.vulnerable),
  };
}
