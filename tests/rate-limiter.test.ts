import { describe, it, expect, beforeEach } from 'vitest';
import { RateLimiter, extractDomain } from '../src/utils/rate-limiter.js';

describe('RateLimiter', () => {
  let limiter: RateLimiter;

  beforeEach(() => {
    limiter = new RateLimiter({ requestsPerSecond: 10, burstSize: 5 });
  });

  describe('canProceed', () => {
    it('should allow initial requests up to burst size', () => {
      expect(limiter.canProceed('test.com')).toBe(true);
      expect(limiter.canProceed('test.com')).toBe(true);
      expect(limiter.canProceed('test.com')).toBe(true);
    });

    it('should track different domains separately', () => {
      expect(limiter.canProceed('domain1.com')).toBe(true);
      expect(limiter.canProceed('domain2.com')).toBe(true);
    });
  });

  describe('acquire', () => {
    it('should consume tokens', async () => {
      await limiter.acquire('test.com');
      expect(limiter.canProceed('test.com')).toBe(true);
    });
  });

  describe('getWaitTime', () => {
    it('should return 0 when tokens available', () => {
      expect(limiter.getWaitTime('test.com')).toBe(0);
    });
  });

  describe('reset', () => {
    it('should reset specific domain', async () => {
      await limiter.acquire('test.com');
      limiter.reset('test.com');
      expect(limiter.getWaitTime('test.com')).toBe(0);
    });

    it('should reset all domains', async () => {
      await limiter.acquire('domain1.com');
      await limiter.acquire('domain2.com');
      limiter.reset();
      expect(limiter.getWaitTime('domain1.com')).toBe(0);
      expect(limiter.getWaitTime('domain2.com')).toBe(0);
    });
  });

  describe('setDomainConfig', () => {
    it('should apply custom config to domain', () => {
      limiter.setDomainConfig('slow.com', { requestsPerSecond: 1, burstSize: 1 });
      expect(limiter.canProceed('slow.com')).toBe(true);
    });
  });
});

describe('extractDomain', () => {
  it('should extract domain from URL', () => {
    expect(extractDomain('https://example.com/path')).toBe('example.com');
    expect(extractDomain('http://sub.example.com:8080/page')).toBe('sub.example.com');
  });

  it('should handle invalid URLs', () => {
    expect(extractDomain('not-a-url')).toBe('unknown');
  });
});
