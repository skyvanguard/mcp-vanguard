import { describe, it, expect, beforeEach, vi } from 'vitest';
import { Cache, createCacheKey, withCache } from '../src/utils/cache.js';

describe('Cache', () => {
  let cache: Cache<string>;

  beforeEach(() => {
    cache = new Cache<string>({ defaultTtl: 1000, maxSize: 10 });
  });

  describe('get/set', () => {
    it('should store and retrieve values', () => {
      cache.set('key1', 'value1');
      expect(cache.get('key1')).toBe('value1');
    });

    it('should return undefined for missing keys', () => {
      expect(cache.get('nonexistent')).toBeUndefined();
    });

    it('should expire entries after TTL', async () => {
      cache.set('key1', 'value1', 50);
      expect(cache.get('key1')).toBe('value1');

      await new Promise(resolve => setTimeout(resolve, 60));
      expect(cache.get('key1')).toBeUndefined();
    });
  });

  describe('has', () => {
    it('should return true for existing keys', () => {
      cache.set('key1', 'value1');
      expect(cache.has('key1')).toBe(true);
    });

    it('should return false for missing keys', () => {
      expect(cache.has('nonexistent')).toBe(false);
    });
  });

  describe('delete', () => {
    it('should remove entries', () => {
      cache.set('key1', 'value1');
      cache.delete('key1');
      expect(cache.get('key1')).toBeUndefined();
    });
  });

  describe('clear', () => {
    it('should remove all entries', () => {
      cache.set('key1', 'value1');
      cache.set('key2', 'value2');
      cache.clear();
      expect(cache.size()).toBe(0);
    });
  });

  describe('maxSize', () => {
    it('should evict oldest entries when full', () => {
      const smallCache = new Cache<string>({ maxSize: 3 });
      smallCache.set('a', '1');
      smallCache.set('b', '2');
      smallCache.set('c', '3');
      smallCache.set('d', '4');

      expect(smallCache.size()).toBe(3);
      expect(smallCache.has('d')).toBe(true);
    });
  });
});

describe('createCacheKey', () => {
  it('should create consistent keys', () => {
    const key1 = createCacheKey('tool', { a: 1 });
    const key2 = createCacheKey('tool', { a: 1 });
    expect(key1).toBe(key2);
  });

  it('should create different keys for different args', () => {
    const key1 = createCacheKey('tool', { a: 1 });
    const key2 = createCacheKey('tool', { a: 2 });
    expect(key1).not.toBe(key2);
  });
});

describe('withCache', () => {
  it('should cache function results', async () => {
    const cache = new Cache({ defaultTtl: 10000 });
    let callCount = 0;

    const fn = async () => {
      callCount++;
      return 'result';
    };

    const result1 = await withCache('test-key', fn);
    const result2 = await withCache('test-key', fn);

    expect(result1).toBe('result');
    expect(result2).toBe('result');
    expect(callCount).toBe(1);
  });
});
