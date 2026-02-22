import { z } from 'zod';

export const gcpBucketCheckSchema = z.object({
  bucket: z.string().describe('GCP bucket name to check'),
  timeout: z.number().default(10000).describe('Per-request timeout in milliseconds'),
});

export type GcpBucketCheckInput = z.infer<typeof gcpBucketCheckSchema>;

export async function gcpBucketCheck(input: GcpBucketCheckInput): Promise<{
  success: boolean;
  bucket: string;
  exists: boolean;
  public: boolean;
  listable: boolean;
  objectCount?: number;
  sampleObjects?: string[];
  error?: string;
}> {
  const { bucket, timeout } = input;

  // GCP Storage XML API
  const url = `https://storage.googleapis.com/${bucket}/`;
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
      return { success: true, bucket, exists: false, public: false, listable: false };
    }

    const listable = body.includes('<ListBucketResult') || body.includes('<Contents>');
    const isPublic = response.status === 200;

    let objectCount: number | undefined;
    let sampleObjects: string[] | undefined;

    if (listable) {
      const keys = [...body.matchAll(/<Key>([^<]+)<\/Key>/g)].map(m => m[1]);
      objectCount = keys.length;
      sampleObjects = keys.slice(0, 10);
    }

    return {
      success: true,
      bucket,
      exists: true,
      public: isPublic,
      listable,
      objectCount,
      sampleObjects,
    };
  } catch (err) {
    return {
      success: false,
      bucket,
      exists: false,
      public: false,
      listable: false,
      error: err instanceof Error ? err.message : 'GCP bucket check failed',
    };
  }
}
