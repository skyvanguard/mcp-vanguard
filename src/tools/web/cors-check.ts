import { z } from 'zod';

export const corsCheckSchema = z.object({
  url: z.string().describe('Target URL to check CORS configuration'),
  origins: z.array(z.string()).default(['https://evil.com', 'null', 'https://attacker.com'])
    .describe('Origins to test'),
  methods: z.array(z.string()).default(['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'])
    .describe('HTTP methods to test'),
  timeout: z.number().default(10000).describe('Request timeout in ms')
});

export type CorsCheckInput = z.infer<typeof corsCheckSchema>;

interface CorsTestResult {
  origin: string;
  allowed: boolean;
  accessControlAllowOrigin?: string;
  accessControlAllowCredentials?: boolean;
  accessControlAllowMethods?: string[];
  accessControlAllowHeaders?: string[];
  accessControlExposeHeaders?: string[];
  accessControlMaxAge?: number;
}

interface CorsIssue {
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  title: string;
  description: string;
  origin?: string;
}

export async function corsCheck(input: CorsCheckInput): Promise<{
  success: boolean;
  url: string;
  results: CorsTestResult[];
  issues: CorsIssue[];
  summary: {
    totalTests: number;
    allowedOrigins: number;
    vulnerabilities: number;
  };
  error?: string;
}> {
  const { url, origins, methods, timeout } = input;

  const results: CorsTestResult[] = [];
  const issues: CorsIssue[] = [];

  try {
    for (const origin of origins) {
      const result = await testOrigin(url, origin, timeout);
      results.push(result);

      if (result.allowed) {
        if (origin === 'null') {
          issues.push({
            severity: 'critical',
            title: 'Null Origin Allowed',
            description: 'Server accepts "null" origin which can be exploited via sandboxed iframes',
            origin
          });
        } else if (origin.includes('evil') || origin.includes('attacker')) {
          issues.push({
            severity: 'critical',
            title: 'Arbitrary Origin Reflection',
            description: `Server reflects arbitrary origin: ${origin}`,
            origin
          });
        }

        if (result.accessControlAllowCredentials) {
          issues.push({
            severity: 'critical',
            title: 'Credentials Allowed with Untrusted Origin',
            description: `Credentials allowed for origin: ${origin}. This enables cookie theft.`,
            origin
          });
        }
      }

      if (result.accessControlAllowOrigin === '*') {
        issues.push({
          severity: 'medium',
          title: 'Wildcard Origin',
          description: 'Access-Control-Allow-Origin is set to "*". While not directly exploitable with credentials, it exposes data to any origin.',
          origin
        });
      }
    }

    const wildcardResult = await testOrigin(url, '*', timeout);
    if (wildcardResult.allowed && wildcardResult.accessControlAllowCredentials) {
      issues.push({
        severity: 'info',
        title: 'Invalid CORS Configuration',
        description: 'Server attempts to use wildcard with credentials (browsers will block this)'
      });
    }

    const preflightResult = await testPreflight(url, 'https://test.com', methods, timeout);
    if (preflightResult.allowedMethods.length > 0) {
      const dangerousMethods = preflightResult.allowedMethods.filter(m =>
        ['PUT', 'DELETE', 'PATCH'].includes(m.toUpperCase())
      );
      if (dangerousMethods.length > 0) {
        issues.push({
          severity: 'medium',
          title: 'Dangerous Methods Allowed',
          description: `Preflight allows potentially dangerous methods: ${dangerousMethods.join(', ')}`
        });
      }
    }

    const allowedCount = results.filter(r => r.allowed).length;

    return {
      success: true,
      url,
      results,
      issues,
      summary: {
        totalTests: results.length,
        allowedOrigins: allowedCount,
        vulnerabilities: issues.filter(i => i.severity === 'critical' || i.severity === 'high').length
      }
    };
  } catch (err) {
    return {
      success: false,
      url,
      results,
      issues,
      summary: { totalTests: 0, allowedOrigins: 0, vulnerabilities: 0 },
      error: err instanceof Error ? err.message : 'CORS check failed'
    };
  }
}

async function testOrigin(url: string, origin: string, timeout: number): Promise<CorsTestResult> {
  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), timeout);

    const response = await fetch(url, {
      method: 'GET',
      headers: {
        'Origin': origin,
        'User-Agent': 'mcp-vanguard/1.0 CORS-Check'
      },
      signal: controller.signal
    });

    clearTimeout(timeoutId);

    const acao = response.headers.get('access-control-allow-origin');
    const acac = response.headers.get('access-control-allow-credentials');
    const acam = response.headers.get('access-control-allow-methods');
    const acah = response.headers.get('access-control-allow-headers');
    const aceh = response.headers.get('access-control-expose-headers');
    const acma = response.headers.get('access-control-max-age');

    return {
      origin,
      allowed: acao === origin || acao === '*',
      accessControlAllowOrigin: acao || undefined,
      accessControlAllowCredentials: acac === 'true',
      accessControlAllowMethods: acam ? acam.split(',').map(m => m.trim()) : undefined,
      accessControlAllowHeaders: acah ? acah.split(',').map(h => h.trim()) : undefined,
      accessControlExposeHeaders: aceh ? aceh.split(',').map(h => h.trim()) : undefined,
      accessControlMaxAge: acma ? parseInt(acma, 10) : undefined
    };
  } catch {
    return {
      origin,
      allowed: false
    };
  }
}

async function testPreflight(
  url: string,
  origin: string,
  methods: string[],
  timeout: number
): Promise<{ allowedMethods: string[]; allowedHeaders: string[] }> {
  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), timeout);

    const response = await fetch(url, {
      method: 'OPTIONS',
      headers: {
        'Origin': origin,
        'Access-Control-Request-Method': 'POST',
        'Access-Control-Request-Headers': 'X-Custom-Header',
        'User-Agent': 'mcp-vanguard/1.0 CORS-Check'
      },
      signal: controller.signal
    });

    clearTimeout(timeoutId);

    const acam = response.headers.get('access-control-allow-methods');
    const acah = response.headers.get('access-control-allow-headers');

    return {
      allowedMethods: acam ? acam.split(',').map(m => m.trim()) : [],
      allowedHeaders: acah ? acah.split(',').map(h => h.trim()) : []
    };
  } catch {
    return { allowedMethods: [], allowedHeaders: [] };
  }
}
