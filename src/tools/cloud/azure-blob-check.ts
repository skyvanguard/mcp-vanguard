import { z } from 'zod';

export const azureBlobCheckSchema = z.object({
  account: z.string().describe('Azure storage account name'),
  containers: z.array(z.string()).default(['$web', 'public', 'data', 'backup', 'files', 'uploads', 'media', 'assets', 'images', 'static'])
    .describe('Container names to check'),
  timeout: z.number().default(10000).describe('Per-request timeout in milliseconds'),
});

export type AzureBlobCheckInput = z.infer<typeof azureBlobCheckSchema>;

interface AzureResult {
  container: string;
  exists: boolean;
  public: boolean;
  listable: boolean;
  blobCount?: number;
  sampleBlobs?: string[];
}

export async function azureBlobCheck(input: AzureBlobCheckInput): Promise<{
  success: boolean;
  account: string;
  results: AzureResult[];
  error?: string;
}> {
  const { account, containers, timeout } = input;
  const results: AzureResult[] = [];

  for (const container of containers) {
    const url = `https://${account}.blob.core.windows.net/${container}?restype=container&comp=list`;
    try {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), timeout);

      const response = await fetch(url, {
        headers: { 'User-Agent': 'mcp-vanguard/2.0' },
        signal: controller.signal,
      });
      clearTimeout(timer);

      const body = await response.text();

      if (response.status === 404) {
        results.push({ container, exists: false, public: false, listable: false });
        continue;
      }

      const listable = body.includes('<EnumerationResults') || body.includes('<Blob>');
      const isPublic = response.status === 200;

      const result: AzureResult = {
        container,
        exists: true,
        public: isPublic,
        listable,
      };

      if (listable) {
        const blobs = [...body.matchAll(/<Name>([^<]+)<\/Name>/g)].map(m => m[1]);
        result.blobCount = blobs.length;
        result.sampleBlobs = blobs.slice(0, 10);
      }

      results.push(result);
    } catch {
      results.push({ container, exists: false, public: false, listable: false });
    }
  }

  return { success: true, account, results };
}
