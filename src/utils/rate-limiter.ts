interface RateLimitConfig {
  requestsPerSecond: number;
  burstSize?: number;
}

interface TokenBucket {
  tokens: number;
  lastRefill: number;
}

export class RateLimiter {
  private buckets = new Map<string, TokenBucket>();
  private defaultConfig: RateLimitConfig;
  private domainConfigs = new Map<string, RateLimitConfig>();

  constructor(defaultConfig: RateLimitConfig = { requestsPerSecond: 10, burstSize: 20 }) {
    this.defaultConfig = defaultConfig;
  }

  setDomainConfig(domain: string, config: RateLimitConfig): void {
    this.domainConfigs.set(domain.toLowerCase(), config);
  }

  private getConfig(domain: string): RateLimitConfig {
    return this.domainConfigs.get(domain.toLowerCase()) ?? this.defaultConfig;
  }

  private getBucket(domain: string): TokenBucket {
    let bucket = this.buckets.get(domain);

    if (!bucket) {
      const config = this.getConfig(domain);
      bucket = {
        tokens: config.burstSize ?? config.requestsPerSecond * 2,
        lastRefill: Date.now()
      };
      this.buckets.set(domain, bucket);
    }

    return bucket;
  }

  private refillBucket(domain: string, bucket: TokenBucket): void {
    const config = this.getConfig(domain);
    const now = Date.now();
    const elapsed = (now - bucket.lastRefill) / 1000;
    const maxTokens = config.burstSize ?? config.requestsPerSecond * 2;

    bucket.tokens = Math.min(maxTokens, bucket.tokens + elapsed * config.requestsPerSecond);
    bucket.lastRefill = now;
  }

  canProceed(domain: string): boolean {
    const bucket = this.getBucket(domain);
    this.refillBucket(domain, bucket);
    return bucket.tokens >= 1;
  }

  async acquire(domain: string): Promise<void> {
    const bucket = this.getBucket(domain);
    this.refillBucket(domain, bucket);

    if (bucket.tokens >= 1) {
      bucket.tokens -= 1;
      return;
    }

    const config = this.getConfig(domain);
    const waitTime = (1 - bucket.tokens) / config.requestsPerSecond * 1000;
    await this.sleep(waitTime);

    this.refillBucket(domain, bucket);
    bucket.tokens -= 1;
  }

  getWaitTime(domain: string): number {
    const bucket = this.getBucket(domain);
    this.refillBucket(domain, bucket);

    if (bucket.tokens >= 1) return 0;

    const config = this.getConfig(domain);
    return (1 - bucket.tokens) / config.requestsPerSecond * 1000;
  }

  reset(domain?: string): void {
    if (domain) {
      this.buckets.delete(domain);
    } else {
      this.buckets.clear();
    }
  }

  private sleep(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
  }
}

export const globalRateLimiter = new RateLimiter({
  requestsPerSecond: 5,
  burstSize: 10
});

globalRateLimiter.setDomainConfig('crt.sh', { requestsPerSecond: 1, burstSize: 3 });
globalRateLimiter.setDomainConfig('web.archive.org', { requestsPerSecond: 2, burstSize: 5 });
globalRateLimiter.setDomainConfig('dns.google', { requestsPerSecond: 10, burstSize: 20 });
globalRateLimiter.setDomainConfig('services.nvd.nist.gov', { requestsPerSecond: 1, burstSize: 2 });

export function extractDomain(url: string): string {
  try {
    return new URL(url).hostname;
  } catch {
    const match = url.match(/https?:\/\/([^/:]+)/);
    return match ? match[1] : 'unknown';
  }
}

export async function rateLimitedFetch(
  url: string,
  options?: RequestInit
): Promise<Response> {
  const domain = extractDomain(url);
  await globalRateLimiter.acquire(domain);
  return fetch(url, options);
}
