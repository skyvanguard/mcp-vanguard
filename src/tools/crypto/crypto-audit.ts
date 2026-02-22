import { z } from 'zod';
import { isInScope } from '../../config.js';

export const cryptoAuditSchema = z.object({
  url: z.string().describe('HTTPS URL to audit TLS/crypto configuration'),
  timeout: z.number().default(15000).describe('Timeout in milliseconds'),
});

export type CryptoAuditInput = z.infer<typeof cryptoAuditSchema>;

interface CryptoIssue {
  category: string;
  issue: string;
  severity: 'info' | 'low' | 'medium' | 'high' | 'critical';
  recommendation: string;
}

export async function cryptoAudit(input: CryptoAuditInput): Promise<{
  success: boolean;
  url: string;
  tlsVersion?: string;
  certificate?: {
    subject: string;
    issuer: string;
    validFrom: string;
    validTo: string;
    daysRemaining: number;
    serialNumber: string;
  };
  issues: CryptoIssue[];
  securityHeaders: Record<string, string | null>;
  error?: string;
}> {
  const { url, timeout } = input;

  let hostname: string;
  try {
    const parsed = new URL(url);
    hostname = parsed.hostname;
    if (parsed.protocol !== 'https:') {
      return {
        success: true, url, issues: [{
          category: 'protocol', issue: 'Not using HTTPS',
          severity: 'critical', recommendation: 'Enable HTTPS/TLS'
        }], securityHeaders: {}
      };
    }
  } catch {
    return { success: false, url, issues: [], securityHeaders: {}, error: 'Invalid URL' };
  }

  if (!isInScope(hostname)) {
    return { success: false, url, issues: [], securityHeaders: {}, error: `Target ${hostname} is not in scope.` };
  }

  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeout);

    const response = await fetch(url, {
      headers: { 'User-Agent': 'mcp-vanguard/2.0' },
      signal: controller.signal,
    });
    clearTimeout(timer);

    const issues: CryptoIssue[] = [];

    // Check security headers
    const headers = response.headers;
    const securityHeaders: Record<string, string | null> = {
      'strict-transport-security': headers.get('strict-transport-security'),
      'content-security-policy': headers.get('content-security-policy'),
      'x-content-type-options': headers.get('x-content-type-options'),
      'x-frame-options': headers.get('x-frame-options'),
      'x-xss-protection': headers.get('x-xss-protection'),
      'referrer-policy': headers.get('referrer-policy'),
      'permissions-policy': headers.get('permissions-policy'),
    };

    // HSTS check
    const hsts = securityHeaders['strict-transport-security'];
    if (!hsts) {
      issues.push({
        category: 'headers',
        issue: 'Missing HSTS header',
        severity: 'high',
        recommendation: 'Add Strict-Transport-Security: max-age=31536000; includeSubDomains',
      });
    } else {
      const maxAge = hsts.match(/max-age=(\d+)/);
      if (maxAge && parseInt(maxAge[1]) < 31536000) {
        issues.push({
          category: 'headers',
          issue: `HSTS max-age too short: ${maxAge[1]}s`,
          severity: 'medium',
          recommendation: 'Set max-age to at least 31536000 (1 year)',
        });
      }
      if (!hsts.includes('includeSubDomains')) {
        issues.push({
          category: 'headers',
          issue: 'HSTS missing includeSubDomains',
          severity: 'low',
          recommendation: 'Add includeSubDomains directive',
        });
      }
    }

    // CSP check
    if (!securityHeaders['content-security-policy']) {
      issues.push({
        category: 'headers',
        issue: 'Missing Content-Security-Policy',
        severity: 'medium',
        recommendation: 'Implement CSP to prevent XSS and injection attacks',
      });
    }

    // X-Content-Type-Options
    if (securityHeaders['x-content-type-options'] !== 'nosniff') {
      issues.push({
        category: 'headers',
        issue: 'Missing X-Content-Type-Options: nosniff',
        severity: 'low',
        recommendation: 'Add X-Content-Type-Options: nosniff',
      });
    }

    // X-Frame-Options
    if (!securityHeaders['x-frame-options']) {
      issues.push({
        category: 'headers',
        issue: 'Missing X-Frame-Options',
        severity: 'medium',
        recommendation: 'Add X-Frame-Options: DENY or SAMEORIGIN',
      });
    }

    // Cookie security
    const setCookie = headers.get('set-cookie') || '';
    if (setCookie) {
      if (!setCookie.toLowerCase().includes('secure')) {
        issues.push({
          category: 'cookies',
          issue: 'Cookie missing Secure flag',
          severity: 'medium',
          recommendation: 'Add Secure flag to all cookies',
        });
      }
      if (!setCookie.toLowerCase().includes('httponly')) {
        issues.push({
          category: 'cookies',
          issue: 'Cookie missing HttpOnly flag',
          severity: 'medium',
          recommendation: 'Add HttpOnly flag to session cookies',
        });
      }
      if (!setCookie.toLowerCase().includes('samesite')) {
        issues.push({
          category: 'cookies',
          issue: 'Cookie missing SameSite attribute',
          severity: 'low',
          recommendation: 'Add SameSite=Strict or SameSite=Lax',
        });
      }
    }

    // Server header disclosure
    const server = headers.get('server');
    if (server) {
      issues.push({
        category: 'info-disclosure',
        issue: `Server header disclosed: ${server}`,
        severity: 'info',
        recommendation: 'Remove or obfuscate Server header',
      });
    }

    const xPoweredBy = headers.get('x-powered-by');
    if (xPoweredBy) {
      issues.push({
        category: 'info-disclosure',
        issue: `X-Powered-By disclosed: ${xPoweredBy}`,
        severity: 'low',
        recommendation: 'Remove X-Powered-By header',
      });
    }

    if (issues.length === 0) {
      issues.push({
        category: 'general',
        issue: 'No issues detected',
        severity: 'info',
        recommendation: 'Configuration appears secure. Consider deeper TLS audit with sslyze/testssl.',
      });
    }

    return {
      success: true,
      url,
      issues,
      securityHeaders,
    };
  } catch (err) {
    return {
      success: false,
      url,
      issues: [],
      securityHeaders: {},
      error: err instanceof Error ? err.message : 'Crypto audit failed',
    };
  }
}
