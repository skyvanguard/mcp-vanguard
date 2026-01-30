import { z } from 'zod';

export const jsEndpointsSchema = z.object({
  url: z.string().describe('URL of JavaScript file or webpage to analyze'),
  deep: z.boolean().default(false).describe('Also fetch and analyze linked JS files'),
  maxFiles: z.number().default(10).describe('Maximum JS files to analyze when deep=true'),
  timeout: z.number().default(30000).describe('Request timeout in ms')
});

export type JsEndpointsInput = z.infer<typeof jsEndpointsSchema>;

interface Endpoint {
  url: string;
  method?: string;
  source: string;
  line?: number;
  context?: string;
}

interface Secret {
  type: string;
  value: string;
  source: string;
  line?: number;
}

interface JsAnalysisResult {
  analyzedFiles: string[];
  endpoints: Endpoint[];
  secrets: Secret[];
  domains: string[];
  parameters: string[];
  comments: string[];
}

const endpointPatterns = [
  { regex: /['"`](\/api\/[^'"`\s]+)['"`]/g, method: undefined },
  { regex: /['"`](\/v\d+\/[^'"`\s]+)['"`]/g, method: undefined },
  { regex: /['"`](\/graphql[^'"`\s]*)['"`]/g, method: undefined },
  { regex: /['"`](\/rest\/[^'"`\s]+)['"`]/g, method: undefined },
  { regex: /fetch\s*\(\s*['"`]([^'"`]+)['"`]/g, method: 'GET' },
  { regex: /axios\.(get|post|put|delete|patch)\s*\(\s*['"`]([^'"`]+)['"`]/gi, method: 'dynamic' },
  { regex: /\$\.(ajax|get|post)\s*\(\s*['"`]([^'"`]+)['"`]/gi, method: 'dynamic' },
  { regex: /\.open\s*\(\s*['"`](GET|POST|PUT|DELETE)['"`]\s*,\s*['"`]([^'"`]+)['"`]/gi, method: 'dynamic' },
  { regex: /url\s*[:=]\s*['"`](https?:\/\/[^'"`\s]+)['"`]/gi, method: undefined },
  { regex: /endpoint\s*[:=]\s*['"`]([^'"`]+)['"`]/gi, method: undefined },
  { regex: /baseURL\s*[:=]\s*['"`]([^'"`]+)['"`]/gi, method: undefined },
  { regex: /['"`](https?:\/\/[^'"`\s]+\/api[^'"`\s]*)['"`]/g, method: undefined }
];

const secretPatterns = [
  { type: 'AWS Access Key', regex: /AKIA[0-9A-Z]{16}/g },
  { type: 'AWS Secret Key', regex: /['"`][A-Za-z0-9/+=]{40}['"`]/g },
  { type: 'Google API Key', regex: /AIza[0-9A-Za-z_-]{35}/g },
  { type: 'GitHub Token', regex: /gh[pousr]_[A-Za-z0-9_]{36,}/g },
  { type: 'Slack Token', regex: /xox[baprs]-[A-Za-z0-9-]+/g },
  { type: 'Stripe Key', regex: /sk_live_[A-Za-z0-9]{24,}/g },
  { type: 'Stripe Test Key', regex: /sk_test_[A-Za-z0-9]{24,}/g },
  { type: 'Firebase', regex: /['"`][A-Za-z0-9_-]*firebase[A-Za-z0-9_-]*['"`]\s*[:=]\s*['"`][^'"`]+['"`]/gi },
  { type: 'JWT Token', regex: /eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*/g },
  { type: 'Private Key', regex: /-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----/g },
  { type: 'Basic Auth', regex: /['"`]Basic [A-Za-z0-9+/=]+['"`]/g },
  { type: 'Bearer Token', regex: /['"`]Bearer [A-Za-z0-9._-]+['"`]/gi },
  { type: 'API Key Generic', regex: /api[_-]?key\s*[:=]\s*['"`]([A-Za-z0-9_-]{16,})['"`]/gi },
  { type: 'Secret Generic', regex: /secret\s*[:=]\s*['"`]([A-Za-z0-9_-]{16,})['"`]/gi }
];

export async function jsEndpoints(input: JsEndpointsInput): Promise<{
  success: boolean;
  url: string;
  result: JsAnalysisResult;
  error?: string;
}> {
  const { url, deep, maxFiles, timeout } = input;

  const result: JsAnalysisResult = {
    analyzedFiles: [],
    endpoints: [],
    secrets: [],
    domains: [],
    parameters: [],
    comments: []
  };

  try {
    const content = await fetchContent(url, timeout);
    if (!content) {
      return {
        success: false,
        url,
        result,
        error: 'Failed to fetch content'
      };
    }

    const isJs = url.endsWith('.js') || content.trim().startsWith('//') ||
                 content.includes('function') || content.includes('const ') ||
                 content.includes('var ') || content.includes('let ');

    if (isJs) {
      analyzeJsContent(content, url, result);
      result.analyzedFiles.push(url);
    } else {
      const jsUrls = extractJsUrls(content, url);

      const filesToAnalyze = deep ? jsUrls.slice(0, maxFiles) : jsUrls.slice(0, 3);

      for (const jsUrl of filesToAnalyze) {
        const jsContent = await fetchContent(jsUrl, timeout);
        if (jsContent) {
          analyzeJsContent(jsContent, jsUrl, result);
          result.analyzedFiles.push(jsUrl);
        }
      }
    }

    result.endpoints = deduplicateEndpoints(result.endpoints);
    result.domains = [...new Set(result.domains)];
    result.parameters = [...new Set(result.parameters)];

    return {
      success: true,
      url,
      result
    };
  } catch (err) {
    return {
      success: false,
      url,
      result,
      error: err instanceof Error ? err.message : 'Analysis failed'
    };
  }
}

async function fetchContent(url: string, timeout: number): Promise<string | null> {
  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), timeout);

    const response = await fetch(url, {
      headers: {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        'Accept': '*/*'
      },
      signal: controller.signal
    });

    clearTimeout(timeoutId);

    if (!response.ok) return null;
    return await response.text();
  } catch {
    return null;
  }
}

function extractJsUrls(html: string, baseUrl: string): string[] {
  const urls: string[] = [];
  const base = new URL(baseUrl);

  const scriptRegex = /<script[^>]+src=['"]([^'"]+)['"][^>]*>/gi;
  let match;

  while ((match = scriptRegex.exec(html)) !== null) {
    let src = match[1];

    if (src.startsWith('//')) {
      src = base.protocol + src;
    } else if (src.startsWith('/')) {
      src = base.origin + src;
    } else if (!src.startsWith('http')) {
      src = new URL(src, baseUrl).href;
    }

    if (!src.includes('google') && !src.includes('facebook') &&
        !src.includes('analytics') && !src.includes('gtag') &&
        !src.includes('jquery.min') && !src.includes('bootstrap.min')) {
      urls.push(src);
    }
  }

  return urls;
}

function analyzeJsContent(content: string, source: string, result: JsAnalysisResult): void {
  for (const pattern of endpointPatterns) {
    const regex = new RegExp(pattern.regex.source, pattern.regex.flags);
    let match;

    while ((match = regex.exec(content)) !== null) {
      let url = match[1];
      let method = pattern.method;

      if (pattern.method === 'dynamic' && match[1]) {
        method = match[1].toUpperCase();
        url = match[2] || match[1];
      }

      if (url && !url.includes('${') && url.length > 1) {
        const line = getLineNumber(content, match.index);
        result.endpoints.push({
          url,
          method,
          source,
          line,
          context: getContext(content, match.index)
        });
      }
    }
  }

  for (const pattern of secretPatterns) {
    const regex = new RegExp(pattern.regex.source, pattern.regex.flags);
    let match;

    while ((match = regex.exec(content)) !== null) {
      const value = match[0];
      if (value.length > 8 && !isFalsePositive(value)) {
        result.secrets.push({
          type: pattern.type,
          value: maskSecret(value),
          source,
          line: getLineNumber(content, match.index)
        });
      }
    }
  }

  const domainRegex = /https?:\/\/([a-zA-Z0-9][-a-zA-Z0-9]*\.)+[a-zA-Z]{2,}/g;
  let domainMatch;
  while ((domainMatch = domainRegex.exec(content)) !== null) {
    try {
      const domain = new URL(domainMatch[0]).hostname;
      result.domains.push(domain);
    } catch {
      // Ignore invalid URLs
    }
  }

  const paramRegex = /[?&]([a-zA-Z_][a-zA-Z0-9_]*)=/g;
  let paramMatch;
  while ((paramMatch = paramRegex.exec(content)) !== null) {
    result.parameters.push(paramMatch[1]);
  }

  const commentRegex = /\/\*[\s\S]*?\*\/|\/\/[^\n]*/g;
  let commentMatch;
  const interestingPatterns = /todo|fixme|hack|bug|password|secret|key|token|admin|debug/i;
  while ((commentMatch = commentRegex.exec(content)) !== null) {
    const comment = commentMatch[0];
    if (interestingPatterns.test(comment)) {
      result.comments.push(comment.slice(0, 200));
    }
  }
}

function getLineNumber(content: string, index: number): number {
  return content.slice(0, index).split('\n').length;
}

function getContext(content: string, index: number): string {
  const start = Math.max(0, index - 30);
  const end = Math.min(content.length, index + 50);
  return content.slice(start, end).replace(/\s+/g, ' ').trim();
}

function deduplicateEndpoints(endpoints: Endpoint[]): Endpoint[] {
  const seen = new Set<string>();
  return endpoints.filter(ep => {
    const key = `${ep.method || ''}:${ep.url}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

function isFalsePositive(value: string): boolean {
  const falsePositives = [
    /^[a-f0-9]{32}$/i,
    /^[a-f0-9]{40}$/i,
    /^[a-f0-9]{64}$/i,
    /example|test|dummy|sample|placeholder/i
  ];
  return falsePositives.some(fp => fp.test(value));
}

function maskSecret(value: string): string {
  if (value.length <= 8) return value;
  const visible = Math.min(8, Math.floor(value.length / 4));
  return value.slice(0, visible) + '*'.repeat(value.length - visible * 2) + value.slice(-visible);
}
