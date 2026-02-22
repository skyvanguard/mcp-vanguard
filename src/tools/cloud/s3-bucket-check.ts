import { z } from 'zod';

export const s3BucketCheckSchema = z.object({
  bucket: z.string().describe('S3 bucket name to check (e.g., "company-backup")'),
  regions: z.array(z.string()).default(['us-east-1', 'us-west-2', 'eu-west-1'])
    .describe('AWS regions to check'),
  timeout: z.number().default(10000).describe('Per-request timeout in milliseconds'),
});

export type S3BucketCheckInput = z.infer<typeof s3BucketCheckSchema>;

interface BucketResult {
  bucket: string;
  exists: boolean;
  public: boolean;
  listable: boolean;
  region?: string;
  objectCount?: number;
  sampleObjects?: string[];
}

export async function s3BucketCheck(input: S3BucketCheckInput): Promise<{
  success: boolean;
  results: BucketResult[];
  error?: string;
}> {
  const { bucket, regions, timeout } = input;
  const results: BucketResult[] = [];

  // Try direct bucket URL (path-style)
  for (const region of regions) {
    const url = `https://${bucket}.s3.${region}.amazonaws.com/`;
    try {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), timeout);

      const response = await fetch(url, {
        method: 'GET',
        headers: { 'User-Agent': 'mcp-vanguard/2.0' },
        signal: controller.signal,
      });
      clearTimeout(timer);

      const body = await response.text();

      if (response.status === 404) continue; // NoSuchBucket

      const exists = response.status !== 404;
      const listable = body.includes('<ListBucketResult') || body.includes('<Contents>');
      const isPublic = response.status === 200;

      const result: BucketResult = {
        bucket,
        exists,
        public: isPublic,
        listable,
        region,
      };

      if (listable) {
        const keys = [...body.matchAll(/<Key>([^<]+)<\/Key>/g)].map(m => m[1]);
        result.objectCount = keys.length;
        result.sampleObjects = keys.slice(0, 10);
      }

      results.push(result);

      if (exists) break; // Found it, no need to check other regions
    } catch {
      continue;
    }
  }

  // Also try virtual-hosted style
  if (results.length === 0) {
    const url = `https://${bucket}.s3.amazonaws.com/`;
    try {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), timeout);
      const response = await fetch(url, {
        headers: { 'User-Agent': 'mcp-vanguard/2.0' },
        signal: controller.signal,
      });
      clearTimeout(timer);

      const body = await response.text();
      const exists = response.status !== 404;

      if (exists) {
        results.push({
          bucket,
          exists: true,
          public: response.status === 200,
          listable: body.includes('<ListBucketResult'),
          region: 'unknown',
        });
      }
    } catch { /* */ }
  }

  if (results.length === 0) {
    results.push({ bucket, exists: false, public: false, listable: false });
  }

  return { success: true, results };
}
