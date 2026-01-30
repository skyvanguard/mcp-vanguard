interface CacheEntry<T> {
  value: T;
  expiresAt: number;
}

export class Cache<T = unknown> {
  private store = new Map<string, CacheEntry<T>>();
  private defaultTtl: number;
  private maxSize: number;

  constructor(options: { defaultTtl?: number; maxSize?: number } = {}) {
    this.defaultTtl = options.defaultTtl ?? 5 * 60 * 1000;
    this.maxSize = options.maxSize ?? 1000;
  }

  get(key: string): T | undefined {
    const entry = this.store.get(key);

    if (!entry) return undefined;

    if (Date.now() > entry.expiresAt) {
      this.store.delete(key);
      return undefined;
    }

    return entry.value;
  }

  set(key: string, value: T, ttl?: number): void {
    if (this.store.size >= this.maxSize) {
      this.evictOldest();
    }

    this.store.set(key, {
      value,
      expiresAt: Date.now() + (ttl ?? this.defaultTtl)
    });
  }

  has(key: string): boolean {
    return this.get(key) !== undefined;
  }

  delete(key: string): boolean {
    return this.store.delete(key);
  }

  clear(): void {
    this.store.clear();
  }

  size(): number {
    this.cleanup();
    return this.store.size;
  }

  private evictOldest(): void {
    let oldestKey: string | undefined;
    let oldestTime = Infinity;

    for (const [key, entry] of this.store) {
      if (entry.expiresAt < oldestTime) {
        oldestTime = entry.expiresAt;
        oldestKey = key;
      }
    }

    if (oldestKey) {
      this.store.delete(oldestKey);
    }
  }

  private cleanup(): void {
    const now = Date.now();
    for (const [key, entry] of this.store) {
      if (entry.expiresAt < now) {
        this.store.delete(key);
      }
    }
  }
}

export function createCacheKey(tool: string, ...args: unknown[]): string {
  return `${tool}:${JSON.stringify(args)}`;
}

export const globalCache = new Cache({
  defaultTtl: 10 * 60 * 1000,
  maxSize: 500
});

export async function withCache<T>(
  key: string,
  fn: () => Promise<T>,
  ttl?: number
): Promise<T> {
  const cached = globalCache.get(key) as T | undefined;
  if (cached !== undefined) {
    return cached;
  }

  const result = await fn();
  globalCache.set(key, result, ttl);
  return result;
}
