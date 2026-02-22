import { z } from 'zod';
import { isInScope } from '../../config.js';

export const exposedEnvCheckSchema = z.object({
  url: z.string().describe('Base URL to check for exposed environment/config files'),
  timeout: z.number().default(10000).describe('Per-request timeout in milliseconds'),
});

export type ExposedEnvCheckInput = z.infer<typeof exposedEnvCheckSchema>;

interface EnvResult {
  path: string;
  found: boolean;
  status: number;
  contentType?: string;
  hasSensitiveData: boolean;
  sensitiveKeys?: string[];
}

const ENV_PATHS = [
  '/.env',
  '/.env.local',
  '/.env.production',
  '/.env.development',
  '/.env.backup',
  '/config.json',
  '/config.yaml',
  '/config.yml',
  '/wp-config.php.bak',
  '/web.config',
  '/.git/config',
  '/.git/HEAD',
  '/.svn/entries',
  '/.DS_Store',
  '/phpinfo.php',
  '/info.php',
  '/server-status',
  '/server-info',
  '/.htpasswd',
  '/.htaccess',
  '/composer.json',
  '/package.json',
  '/Dockerfile',
  '/docker-compose.yml',
  '/.dockerenv',
  '/robots.txt',
  '/sitemap.xml',
  '/crossdomain.xml',
  '/.well-known/security.txt',
  '/backup.sql',
  '/dump.sql',
  '/database.sql',
];

const SENSITIVE_PATTERNS = [
  /(?:password|passwd|pwd)\s*[=:]/i,
  /(?:secret|token|key|api_key|apikey)\s*[=:]/i,
  /(?:database_url|db_url|connection_string)\s*[=:]/i,
  /(?:aws_access_key|aws_secret|s3_key)\s*[=:]/i,
  /(?:smtp_password|mail_password)\s*[=:]/i,
  /(?:private_key|ssh_key)\s*[=:]/i,
  /(?:BEGIN\s+(?:RSA|DSA|EC|OPENSSH)\s+PRIVATE\s+KEY)/,
  /(?:mysql|postgres|mongodb):\/\//i,
];

export async function exposedEnvCheck(input: ExposedEnvCheckInput): Promise<{
  success: boolean;
  url: string;
  results: EnvResult[];
  exposedCount: number;
  error?: string;
}> {
  const { url, timeout } = input;

  let hostname: string;
  let baseUrl: string;
  try {
    const parsed = new URL(url);
    hostname = parsed.hostname;
    baseUrl = `${parsed.protocol}//${parsed.host}`;
  } catch {
    return { success: false, url, results: [], exposedCount: 0, error: 'Invalid URL' };
  }

  if (!isInScope(hostname)) {
    return { success: false, url, results: [], exposedCount: 0, error: `Target ${hostname} is not in scope.` };
  }

  const results: EnvResult[] = [];

  for (const path of ENV_PATHS) {
    const fullUrl = `${baseUrl}${path}`;

    try {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), timeout);

      const response = await fetch(fullUrl, {
        headers: { 'User-Agent': 'mcp-vanguard/2.0' },
        signal: controller.signal,
        redirect: 'follow',
      });
      clearTimeout(timer);

      if (response.status === 200) {
        const contentType = response.headers.get('content-type') || '';
        const body = await response.text();

        // Skip HTML error pages
        if (contentType.includes('text/html') && body.includes('<!DOCTYPE')) {
          continue;
        }

        const sensitiveKeys: string[] = [];
        for (const pattern of SENSITIVE_PATTERNS) {
          const match = body.match(pattern);
          if (match) sensitiveKeys.push(match[0].slice(0, 30));
        }

        results.push({
          path,
          found: true,
          status: 200,
          contentType,
          hasSensitiveData: sensitiveKeys.length > 0,
          sensitiveKeys: sensitiveKeys.length > 0 ? sensitiveKeys : undefined,
        });
      }
    } catch {
      // Timeout or network error — skip
    }
  }

  return {
    success: true,
    url,
    results,
    exposedCount: results.filter(r => r.found).length,
  };
}
