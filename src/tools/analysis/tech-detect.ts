import { z } from 'zod';
import { isInScope } from '../../config.js';

export const techDetectSchema = z.object({
  url: z.string().describe('URL to detect technologies'),
  timeout: z.number().default(15000).describe('Timeout in milliseconds'),
});

export type TechDetectInput = z.infer<typeof techDetectSchema>;

interface TechMatch {
  name: string;
  category: string;
  confidence: 'high' | 'medium' | 'low';
  evidence: string;
}

const TECH_SIGNATURES: Array<{
  name: string;
  category: string;
  headers?: Array<{ header: string; pattern: RegExp }>;
  body?: RegExp[];
  cookies?: string[];
}> = [
  { name: 'Nginx', category: 'Web Server', headers: [{ header: 'server', pattern: /nginx/i }] },
  { name: 'Apache', category: 'Web Server', headers: [{ header: 'server', pattern: /apache/i }] },
  { name: 'IIS', category: 'Web Server', headers: [{ header: 'server', pattern: /microsoft-iis/i }] },
  { name: 'Express.js', category: 'Framework', headers: [{ header: 'x-powered-by', pattern: /express/i }] },
  { name: 'PHP', category: 'Language', headers: [{ header: 'x-powered-by', pattern: /php/i }] },
  { name: 'ASP.NET', category: 'Framework', headers: [{ header: 'x-powered-by', pattern: /asp\.net/i }], cookies: ['ASP.NET_SessionId'] },
  { name: 'Django', category: 'Framework', cookies: ['csrftoken'], body: [/csrfmiddlewaretoken/] },
  { name: 'Laravel', category: 'Framework', cookies: ['laravel_session'], body: [/laravel/i] },
  { name: 'Ruby on Rails', category: 'Framework', headers: [{ header: 'x-powered-by', pattern: /phusion/i }], cookies: ['_session_id'] },
  { name: 'WordPress', category: 'CMS', body: [/wp-content/i, /wp-includes/i, /wp-json/i] },
  { name: 'Drupal', category: 'CMS', headers: [{ header: 'x-generator', pattern: /drupal/i }], body: [/\/sites\/default\//] },
  { name: 'Joomla', category: 'CMS', body: [/\/media\/jui\//i, /joomla/i] },
  { name: 'React', category: 'JS Framework', body: [/__NEXT_DATA__/, /react-root/, /_next\/static/] },
  { name: 'Next.js', category: 'JS Framework', headers: [{ header: 'x-powered-by', pattern: /next\.js/i }], body: [/__NEXT_DATA__/] },
  { name: 'Vue.js', category: 'JS Framework', body: [/vue\./i, /v-cloak/, /nuxt/i] },
  { name: 'Angular', category: 'JS Framework', body: [/ng-version/, /angular/i] },
  { name: 'jQuery', category: 'JS Library', body: [/jquery[.-]\d/i] },
  { name: 'Bootstrap', category: 'CSS Framework', body: [/bootstrap[.-]\d/i, /class=".*\bcontainer\b.*\brow\b/] },
  { name: 'Cloudflare', category: 'CDN/WAF', headers: [{ header: 'server', pattern: /cloudflare/i }, { header: 'cf-ray', pattern: /.+/ }] },
  { name: 'AWS CloudFront', category: 'CDN', headers: [{ header: 'x-amz-cf-id', pattern: /.+/ }] },
  { name: 'Google Analytics', category: 'Analytics', body: [/google-analytics\.com/, /gtag\/js/] },
  { name: 'Varnish', category: 'Cache', headers: [{ header: 'x-varnish', pattern: /.+/ }, { header: 'via', pattern: /varnish/i }] },
];

export async function techDetect(input: TechDetectInput): Promise<{
  success: boolean;
  url: string;
  technologies: TechMatch[];
  categories: Record<string, string[]>;
  error?: string;
}> {
  const { url, timeout } = input;

  let hostname: string;
  try {
    hostname = new URL(url).hostname;
  } catch {
    return { success: false, url, technologies: [], categories: {}, error: 'Invalid URL' };
  }

  if (!isInScope(hostname)) {
    return { success: false, url, technologies: [], categories: {}, error: `Target ${hostname} is not in scope.` };
  }

  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeout);

    const response = await fetch(url, {
      headers: { 'User-Agent': 'mcp-vanguard/2.0' },
      signal: controller.signal,
      redirect: 'follow',
    });
    clearTimeout(timer);

    const body = await response.text();
    const headers = response.headers;
    const cookieHeader = headers.get('set-cookie') || '';
    const technologies: TechMatch[] = [];

    for (const sig of TECH_SIGNATURES) {
      let matched = false;
      let evidence = '';

      // Check headers
      if (sig.headers) {
        for (const h of sig.headers) {
          const val = headers.get(h.header);
          if (val && h.pattern.test(val)) {
            matched = true;
            evidence = `Header ${h.header}: ${val}`;
            break;
          }
        }
      }

      // Check cookies
      if (!matched && sig.cookies) {
        for (const cookie of sig.cookies) {
          if (cookieHeader.includes(cookie)) {
            matched = true;
            evidence = `Cookie: ${cookie}`;
            break;
          }
        }
      }

      // Check body
      if (!matched && sig.body) {
        for (const pattern of sig.body) {
          if (pattern.test(body)) {
            matched = true;
            const m = body.match(pattern);
            evidence = `Body match: ${m?.[0]?.slice(0, 50)}`;
            break;
          }
        }
      }

      if (matched) {
        technologies.push({
          name: sig.name,
          category: sig.category,
          confidence: sig.headers && evidence.startsWith('Header') ? 'high' : 'medium',
          evidence,
        });
      }
    }

    // Group by category
    const categories: Record<string, string[]> = {};
    for (const t of technologies) {
      if (!categories[t.category]) categories[t.category] = [];
      categories[t.category].push(t.name);
    }

    return { success: true, url, technologies, categories };
  } catch (err) {
    return {
      success: false, url, technologies: [], categories: {},
      error: err instanceof Error ? err.message : 'Tech detection failed',
    };
  }
}
