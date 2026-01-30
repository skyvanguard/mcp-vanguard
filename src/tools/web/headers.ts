import { z } from 'zod';

export const headersCheckSchema = z.object({
  url: z.string().describe('Target URL to check security headers'),
  followRedirects: z.boolean().default(true).describe('Follow HTTP redirects'),
  timeout: z.number().default(30000).describe('Request timeout in milliseconds')
});

export type HeadersCheckInput = z.infer<typeof headersCheckSchema>;

interface SecurityHeader {
  name: string;
  present: boolean;
  value?: string;
  grade: 'good' | 'warning' | 'bad' | 'info';
  recommendation?: string;
}

interface HeadersResult {
  url: string;
  statusCode: number;
  headers: Record<string, string>;
  securityHeaders: SecurityHeader[];
  score: number;
  grade: string;
}

const securityHeadersConfig: Array<{
  name: string;
  header: string;
  required: boolean;
  validator?: (value: string) => { grade: 'good' | 'warning' | 'bad'; message?: string };
}> = [
  {
    name: 'Strict-Transport-Security',
    header: 'strict-transport-security',
    required: true,
    validator: (value) => {
      const maxAge = value.match(/max-age=(\d+)/i);
      if (!maxAge) return { grade: 'bad', message: 'Missing max-age directive' };
      const age = parseInt(maxAge[1], 10);
      if (age < 31536000) return { grade: 'warning', message: 'max-age should be at least 1 year (31536000)' };
      if (!value.toLowerCase().includes('includesubdomains')) {
        return { grade: 'warning', message: 'Consider adding includeSubDomains' };
      }
      return { grade: 'good' };
    }
  },
  {
    name: 'Content-Security-Policy',
    header: 'content-security-policy',
    required: true,
    validator: (value) => {
      if (value.includes("'unsafe-inline'") || value.includes("'unsafe-eval'")) {
        return { grade: 'warning', message: 'Contains unsafe directives' };
      }
      if (!value.includes('default-src')) {
        return { grade: 'warning', message: 'Missing default-src directive' };
      }
      return { grade: 'good' };
    }
  },
  {
    name: 'X-Frame-Options',
    header: 'x-frame-options',
    required: true,
    validator: (value) => {
      const upper = value.toUpperCase();
      if (upper === 'DENY' || upper === 'SAMEORIGIN') {
        return { grade: 'good' };
      }
      return { grade: 'warning', message: 'Should be DENY or SAMEORIGIN' };
    }
  },
  {
    name: 'X-Content-Type-Options',
    header: 'x-content-type-options',
    required: true,
    validator: (value) => {
      if (value.toLowerCase() === 'nosniff') {
        return { grade: 'good' };
      }
      return { grade: 'warning', message: 'Should be nosniff' };
    }
  },
  {
    name: 'X-XSS-Protection',
    header: 'x-xss-protection',
    required: false,
    validator: (value) => {
      if (value === '0') {
        return { grade: 'good', message: 'Disabled (recommended with CSP)' };
      }
      if (value.includes('1') && value.includes('mode=block')) {
        return { grade: 'good' };
      }
      return { grade: 'warning', message: 'Consider disabling (0) when using CSP' };
    }
  },
  {
    name: 'Referrer-Policy',
    header: 'referrer-policy',
    required: true,
    validator: (value) => {
      const secure = ['no-referrer', 'strict-origin', 'strict-origin-when-cross-origin', 'same-origin'];
      if (secure.some(s => value.toLowerCase().includes(s))) {
        return { grade: 'good' };
      }
      return { grade: 'warning', message: 'Consider a more restrictive policy' };
    }
  },
  {
    name: 'Permissions-Policy',
    header: 'permissions-policy',
    required: false,
    validator: () => ({ grade: 'good' })
  },
  {
    name: 'Cross-Origin-Opener-Policy',
    header: 'cross-origin-opener-policy',
    required: false,
    validator: (value) => {
      if (value === 'same-origin') {
        return { grade: 'good' };
      }
      return { grade: 'warning', message: 'Consider same-origin for better isolation' };
    }
  },
  {
    name: 'Cross-Origin-Resource-Policy',
    header: 'cross-origin-resource-policy',
    required: false,
    validator: () => ({ grade: 'good' })
  },
  {
    name: 'Cross-Origin-Embedder-Policy',
    header: 'cross-origin-embedder-policy',
    required: false,
    validator: () => ({ grade: 'good' })
  }
];

export async function headersCheck(input: HeadersCheckInput): Promise<{
  success: boolean;
  result: HeadersResult | null;
  error?: string;
}> {
  const { url, followRedirects, timeout } = input;

  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), timeout);

    const response = await fetch(url, {
      method: 'HEAD',
      redirect: followRedirects ? 'follow' : 'manual',
      signal: controller.signal,
      headers: {
        'User-Agent': 'mcp-vanguard/1.0 SecurityHeadersCheck'
      }
    });

    clearTimeout(timeoutId);

    const headers: Record<string, string> = {};
    response.headers.forEach((value, key) => {
      headers[key.toLowerCase()] = value;
    });

    const securityHeaders: SecurityHeader[] = [];
    let score = 0;
    const maxScore = securityHeadersConfig.filter(h => h.required).length * 10;

    for (const config of securityHeadersConfig) {
      const value = headers[config.header];

      if (!value) {
        securityHeaders.push({
          name: config.name,
          present: false,
          grade: config.required ? 'bad' : 'info',
          recommendation: config.required
            ? `Add ${config.name} header for better security`
            : `Consider adding ${config.name} header`
        });
      } else {
        const validation = config.validator ? config.validator(value) : { grade: 'good' as const };

        securityHeaders.push({
          name: config.name,
          present: true,
          value,
          grade: validation.grade,
          recommendation: validation.message
        });

        if (config.required) {
          if (validation.grade === 'good') score += 10;
          else if (validation.grade === 'warning') score += 5;
        }
      }
    }

    checkInsecureHeaders(headers, securityHeaders);

    const percentage = Math.round((score / maxScore) * 100);
    const grade = calculateGrade(percentage);

    return {
      success: true,
      result: {
        url: response.url,
        statusCode: response.status,
        headers,
        securityHeaders,
        score: percentage,
        grade
      }
    };
  } catch (err) {
    return {
      success: false,
      result: null,
      error: err instanceof Error ? err.message : 'Request failed'
    };
  }
}

function checkInsecureHeaders(
  headers: Record<string, string>,
  results: SecurityHeader[]
): void {
  const insecureHeaders = [
    { header: 'server', message: 'Server version disclosure' },
    { header: 'x-powered-by', message: 'Technology disclosure' },
    { header: 'x-aspnet-version', message: 'ASP.NET version disclosure' },
    { header: 'x-aspnetmvc-version', message: 'ASP.NET MVC version disclosure' }
  ];

  for (const { header, message } of insecureHeaders) {
    if (headers[header]) {
      results.push({
        name: header,
        present: true,
        value: headers[header],
        grade: 'warning',
        recommendation: `Remove ${header} header to prevent ${message}`
      });
    }
  }
}

function calculateGrade(percentage: number): string {
  if (percentage >= 90) return 'A+';
  if (percentage >= 80) return 'A';
  if (percentage >= 70) return 'B';
  if (percentage >= 60) return 'C';
  if (percentage >= 50) return 'D';
  return 'F';
}
