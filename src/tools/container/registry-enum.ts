import { z } from 'zod';
import { isInScope } from '../../config.js';

export const registryEnumSchema = z.object({
  url: z.string().describe('Container registry URL (e.g., "https://registry.example.com")'),
  timeout: z.number().default(15000).describe('Timeout in milliseconds'),
});

export type RegistryEnumInput = z.infer<typeof registryEnumSchema>;

interface RegistryResult {
  check: string;
  found: boolean;
  data?: string;
}

export async function registryEnum(input: RegistryEnumInput): Promise<{
  success: boolean;
  url: string;
  accessible: boolean;
  repositories?: string[];
  results: RegistryResult[];
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
    return { success: false, url, accessible: false, results: [], error: 'Invalid URL' };
  }

  if (!isInScope(hostname)) {
    return { success: false, url, accessible: false, results: [], error: `Target ${hostname} is not in scope.` };
  }

  const results: RegistryResult[] = [];

  // Check v2 API
  const v2Accessible = await checkUrl(`${baseUrl}/v2/`, timeout);
  results.push({
    check: 'Registry v2 API',
    found: v2Accessible.accessible,
    data: v2Accessible.accessible ? `Status: ${v2Accessible.status}` : 'Not accessible',
  });

  if (!v2Accessible.accessible) {
    return {
      success: true,
      url,
      accessible: false,
      results,
    };
  }

  // List repositories (catalog)
  let repositories: string[] | undefined;
  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeout);
    const catalogResp = await fetch(`${baseUrl}/v2/_catalog`, {
      headers: { 'User-Agent': 'mcp-vanguard/2.0' },
      signal: controller.signal,
    });
    clearTimeout(timer);

    if (catalogResp.status === 200) {
      const data = await catalogResp.json() as { repositories?: string[] };
      repositories = data.repositories?.slice(0, 50);
      results.push({
        check: 'Repository listing',
        found: true,
        data: `${repositories?.length || 0} repositories found`,
      });

      // Get tags for first few repos
      if (repositories) {
        for (const repo of repositories.slice(0, 5)) {
          try {
            const tagsResp = await fetch(`${baseUrl}/v2/${repo}/tags/list`, {
              headers: { 'User-Agent': 'mcp-vanguard/2.0' },
              signal: AbortSignal.timeout(timeout),
            });
            if (tagsResp.status === 200) {
              const tagsData = await tagsResp.json() as { tags?: string[] };
              results.push({
                check: `Tags for ${repo}`,
                found: true,
                data: `Tags: ${(tagsData.tags || []).slice(0, 10).join(', ')}`,
              });
            }
          } catch { /* */ }
        }
      }
    } else {
      results.push({
        check: 'Repository listing',
        found: false,
        data: `Catalog returned ${catalogResp.status} (auth required?)`,
      });
    }
  } catch {
    results.push({ check: 'Repository listing', found: false, data: 'Failed to fetch catalog' });
  }

  return {
    success: true,
    url,
    accessible: true,
    repositories,
    results,
  };
}

async function checkUrl(url: string, timeout: number): Promise<{ accessible: boolean; status: number }> {
  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeout);
    const response = await fetch(url, {
      headers: { 'User-Agent': 'mcp-vanguard/2.0' },
      signal: controller.signal,
    });
    clearTimeout(timer);
    return { accessible: response.status === 200 || response.status === 401, status: response.status };
  } catch {
    return { accessible: false, status: 0 };
  }
}
