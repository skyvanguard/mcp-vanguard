import { z } from 'zod';
import { createHash } from 'crypto';

export const faviconHashSchema = z.object({
  url: z.string().describe('URL to fetch favicon from (will try /favicon.ico if no path)'),
  timeout: z.number().default(10000).describe('Timeout in milliseconds')
});

export type FaviconHashInput = z.infer<typeof faviconHashSchema>;

export async function faviconHash(input: FaviconHashInput): Promise<{
  success: boolean;
  url: string;
  hashes: {
    md5?: string;
    sha256?: string;
    mmh3?: number;
  };
  shodanQuery?: string;
  size?: number;
  contentType?: string;
  error?: string;
}> {
  const { url, timeout } = input;

  // Determine favicon URL
  let faviconUrl = url;
  try {
    const parsed = new URL(url);
    if (parsed.pathname === '/' || !parsed.pathname.includes('.')) {
      faviconUrl = `${parsed.origin}/favicon.ico`;
    }
  } catch {
    return { success: false, url, hashes: {}, error: 'Invalid URL' };
  }

  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeout);

    const response = await fetch(faviconUrl, {
      headers: {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
      },
      signal: controller.signal
    });
    clearTimeout(timer);

    if (!response.ok) {
      return { success: false, url: faviconUrl, hashes: {}, error: `HTTP ${response.status}` };
    }

    const buffer = Buffer.from(await response.arrayBuffer());

    const md5 = createHash('md5').update(buffer).digest('hex');
    const sha256 = createHash('sha256').update(buffer).digest('hex');

    // MurmurHash3 for Shodan favicon search
    const b64 = buffer.toString('base64');
    const mmh3 = murmurHash3(b64);

    return {
      success: true,
      url: faviconUrl,
      hashes: { md5, sha256, mmh3 },
      shodanQuery: `http.favicon.hash:${mmh3}`,
      size: buffer.length,
      contentType: response.headers.get('content-type') || undefined
    };
  } catch (err) {
    return {
      success: false,
      url: faviconUrl,
      hashes: {},
      error: err instanceof Error ? err.message : 'Failed to fetch favicon'
    };
  }
}

// MurmurHash3 (32-bit) implementation matching Shodan's
function murmurHash3(key: string, seed: number = 0): number {
  const data = Buffer.from(key, 'utf8');
  const len = data.length;
  const nblocks = Math.floor(len / 4);

  let h1 = seed >>> 0;
  const c1 = 0xcc9e2d51;
  const c2 = 0x1b873593;

  for (let i = 0; i < nblocks; i++) {
    let k1 = data.readUInt32LE(i * 4);

    k1 = Math.imul(k1, c1);
    k1 = (k1 << 15) | (k1 >>> 17);
    k1 = Math.imul(k1, c2);

    h1 ^= k1;
    h1 = (h1 << 13) | (h1 >>> 19);
    h1 = Math.imul(h1, 5) + 0xe6546b64;
  }

  const tail = nblocks * 4;
  let k1 = 0;

  switch (len & 3) {
    case 3: k1 ^= data[tail + 2] << 16;
    // falls through
    case 2: k1 ^= data[tail + 1] << 8;
    // falls through
    case 1:
      k1 ^= data[tail];
      k1 = Math.imul(k1, c1);
      k1 = (k1 << 15) | (k1 >>> 17);
      k1 = Math.imul(k1, c2);
      h1 ^= k1;
  }

  h1 ^= len;

  // fmix32
  h1 ^= h1 >>> 16;
  h1 = Math.imul(h1, 0x85ebca6b);
  h1 ^= h1 >>> 13;
  h1 = Math.imul(h1, 0xc2b2ae35);
  h1 ^= h1 >>> 16;

  return h1 | 0; // Convert to signed 32-bit
}
