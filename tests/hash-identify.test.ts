import { describe, it, expect } from 'vitest';
import { hashIdentify } from '../src/tools/crypto/hash-identify.js';

describe('hashIdentify', () => {
  it('should identify MD5 hash', async () => {
    const result = await hashIdentify({ hash: '5d41402abc4b2a76b9719d911017c592' });
    expect(result.success).toBe(true);
    expect(result.length).toBe(32);
    expect(result.matches.some(m => m.algorithm === 'MD5')).toBe(true);
  });

  it('should identify SHA-1 hash', async () => {
    const result = await hashIdentify({ hash: 'aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d' });
    expect(result.success).toBe(true);
    expect(result.length).toBe(40);
    expect(result.matches.some(m => m.algorithm === 'SHA-1')).toBe(true);
  });

  it('should identify SHA-256 hash', async () => {
    const result = await hashIdentify({ hash: '2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824' });
    expect(result.success).toBe(true);
    expect(result.length).toBe(64);
    expect(result.matches.some(m => m.algorithm === 'SHA-256')).toBe(true);
  });

  it('should identify bcrypt hash with high confidence', async () => {
    const result = await hashIdentify({ hash: '$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy' });
    expect(result.success).toBe(true);
    expect(result.mostLikely).toBe('bcrypt');
    const bcrypt = result.matches.find(m => m.algorithm === 'bcrypt');
    expect(bcrypt).toBeDefined();
    expect(bcrypt!.confidence).toBe('high');
    expect(bcrypt!.hashcat_mode).toBe(3200);
  });

  it('should identify SHA-512-crypt', async () => {
    // Real SHA-512-crypt: $6$salt$86-char-hash
    // SHA-512-crypt: $6$salt$86-chars (exactly 86 base64 chars after last $)
    const result = await hashIdentify({ hash: '$6$saltsalt$qFmFH.bQmmtXzyBY0s9v7Oicd2z4XSIecDzlB5KiA2/jctKu9YterLDp284Rd8J52aSKRwP2CLatBEBQ30PeOR' });
    expect(result.success).toBe(true);
    expect(result.matches.some(m => m.algorithm === 'SHA-512-crypt')).toBe(true);
  });

  it('should identify MySQL hash', async () => {
    const result = await hashIdentify({ hash: '*6C8989366EAF6BCBBAFE8C5A05228C26EB1A56E8' });
    expect(result.success).toBe(true);
    expect(result.matches.some(m => m.algorithm === 'MySQL 4.1+')).toBe(true);
  });

  it('should provide hashcat mode and john format', async () => {
    const result = await hashIdentify({ hash: '5d41402abc4b2a76b9719d911017c592' });
    const md5 = result.matches.find(m => m.algorithm === 'MD5');
    expect(md5).toBeDefined();
    expect(md5!.hashcat_mode).toBe(0);
    expect(md5!.john_format).toBe('raw-md5');
  });

  it('should handle whitespace in hash', async () => {
    const result = await hashIdentify({ hash: '  5d41402abc4b2a76b9719d911017c592  ' });
    expect(result.success).toBe(true);
    expect(result.length).toBe(32);
  });
});
