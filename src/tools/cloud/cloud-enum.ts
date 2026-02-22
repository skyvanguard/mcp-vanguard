import { z } from 'zod';

export const cloudEnumSchema = z.object({
  keyword: z.string().describe('Company/keyword to enumerate cloud resources for'),
  providers: z.array(z.enum(['aws', 'azure', 'gcp'])).default(['aws', 'azure', 'gcp'])
    .describe('Cloud providers to check'),
  timeout: z.number().default(8000).describe('Per-request timeout in milliseconds'),
});

export type CloudEnumInput = z.infer<typeof cloudEnumSchema>;

interface CloudResource {
  provider: string;
  type: string;
  name: string;
  url: string;
  exists: boolean;
  public: boolean;
}

const PERMUTATIONS = (keyword: string): string[] => {
  const k = keyword.toLowerCase().replace(/[^a-z0-9]/g, '');
  return [
    k, `${k}-dev`, `${k}-staging`, `${k}-prod`, `${k}-backup`,
    `${k}-data`, `${k}-assets`, `${k}-media`, `${k}-static`,
    `${k}-public`, `${k}-private`, `${k}-internal`, `${k}-test`,
    `${k}-logs`, `${k}-uploads`, `${k}-files`, `${k}-cdn`,
  ];
};

export async function cloudEnum(input: CloudEnumInput): Promise<{
  success: boolean;
  keyword: string;
  resources: CloudResource[];
  found: number;
  error?: string;
}> {
  const { keyword, providers, timeout } = input;
  const names = PERMUTATIONS(keyword);
  const resources: CloudResource[] = [];

  for (const name of names) {
    const checks: Promise<CloudResource | null>[] = [];

    if (providers.includes('aws')) {
      checks.push(checkResource(`https://${name}.s3.amazonaws.com/`, 'aws', 'S3 Bucket', name, timeout));
    }
    if (providers.includes('azure')) {
      checks.push(checkResource(`https://${name}.blob.core.windows.net/?comp=list`, 'azure', 'Blob Storage', name, timeout));
    }
    if (providers.includes('gcp')) {
      checks.push(checkResource(`https://storage.googleapis.com/${name}/`, 'gcp', 'GCS Bucket', name, timeout));
    }

    const results = await Promise.all(checks);
    for (const r of results) {
      if (r && r.exists) resources.push(r);
    }
  }

  return {
    success: true,
    keyword,
    resources,
    found: resources.length,
  };
}

async function checkResource(
  url: string,
  provider: string,
  type: string,
  name: string,
  timeout: number,
): Promise<CloudResource | null> {
  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeout);

    const response = await fetch(url, {
      method: 'HEAD',
      headers: { 'User-Agent': 'mcp-vanguard/2.0' },
      signal: controller.signal,
    });
    clearTimeout(timer);

    if (response.status === 404 || response.status === 0) return null;

    return {
      provider,
      type,
      name,
      url,
      exists: true,
      public: response.status === 200,
    };
  } catch {
    return null;
  }
}
