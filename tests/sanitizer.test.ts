import { describe, it, expect } from 'vitest';
import {
  sanitizeForShell,
  sanitizeDomain,
  sanitizeUrl,
  sanitizePath,
  escapeShellArg,
  isValidDomain,
  isValidIP,
  isPrivateIP,
  maskSensitive,
  sanitizeOutput,
  SecurityError
} from '../src/utils/sanitizer.js';

describe('sanitizeForShell', () => {
  it('should remove dangerous shell characters', () => {
    expect(sanitizeForShell('test; rm -rf /')).toBe('test rm -rf /');
    expect(sanitizeForShell('test | cat /etc/passwd')).toBe('test  cat /etc/passwd');
    expect(sanitizeForShell('test && echo pwned')).toBe('test  echo pwned');
  });

  it('should handle empty input', () => {
    expect(sanitizeForShell('')).toBe('');
  });

  it('should preserve safe characters', () => {
    expect(sanitizeForShell('example.com')).toBe('example.com');
    expect(sanitizeForShell('192.168.1.1')).toBe('192.168.1.1');
  });
});

describe('sanitizeDomain', () => {
  it('should normalize domain input', () => {
    expect(sanitizeDomain('EXAMPLE.COM')).toBe('example.com');
    expect(sanitizeDomain('https://example.com/')).toBe('example.com');
    expect(sanitizeDomain('example.com:8080')).toBe('example.com');
  });

  it('should reject invalid domains', () => {
    expect(() => sanitizeDomain('not a domain!')).toThrow(SecurityError);
  });

  it('should accept valid IPs', () => {
    expect(sanitizeDomain('192.168.1.1')).toBe('192.168.1.1');
  });
});

describe('sanitizeUrl', () => {
  it('should accept valid HTTPS URLs', () => {
    expect(sanitizeUrl('https://example.com/path')).toBe('https://example.com/path');
  });

  it('should reject non-HTTP protocols', () => {
    expect(() => sanitizeUrl('file:///etc/passwd')).toThrow(SecurityError);
    expect(() => sanitizeUrl('ftp://example.com')).toThrow(SecurityError);
  });

  it('should reject URLs with credentials', () => {
    expect(() => sanitizeUrl('https://user:pass@example.com')).toThrow(SecurityError);
  });

  it('should reject private IPs', () => {
    expect(() => sanitizeUrl('http://192.168.1.1')).toThrow(SecurityError);
    expect(() => sanitizeUrl('http://10.0.0.1')).toThrow(SecurityError);
    expect(() => sanitizeUrl('http://127.0.0.1')).toThrow(SecurityError);
  });
});

describe('sanitizePath', () => {
  it('should reject path traversal', () => {
    expect(() => sanitizePath('../../../etc/passwd')).toThrow(SecurityError);
    expect(() => sanitizePath('..\\..\\windows\\system32')).toThrow(SecurityError);
  });

  it('should normalize path separators', () => {
    expect(sanitizePath('path\\to\\file')).toBe('path/to/file');
  });
});

describe('escapeShellArg', () => {
  it('should quote arguments with special characters', () => {
    const escaped = escapeShellArg('hello world');
    expect(escaped).toContain('hello world');
  });

  it('should handle empty input', () => {
    expect(escapeShellArg('')).toBe("''");
  });

  it('should escape arguments appropriately for platform', () => {
    // On Windows, all arguments get quoted
    // On Unix, safe arguments pass through
    const escaped = escapeShellArg('simple');
    if (process.platform === 'win32') {
      expect(escaped).toBe('"simple"');
    } else {
      expect(escaped).toBe('simple');
    }
  });
});

describe('isValidDomain', () => {
  it('should validate normal domains', () => {
    expect(isValidDomain('example.com')).toBe(true);
    expect(isValidDomain('sub.example.com')).toBe(true);
    expect(isValidDomain('*.example.com')).toBe(true);
  });

  it('should reject invalid domains', () => {
    expect(isValidDomain('')).toBe(false);
    expect(isValidDomain('a'.repeat(300))).toBe(false);
    expect(isValidDomain('-invalid.com')).toBe(false);
  });
});

describe('isValidIP', () => {
  it('should validate IPv4 addresses', () => {
    expect(isValidIP('192.168.1.1')).toBe(true);
    expect(isValidIP('10.0.0.1')).toBe(true);
    expect(isValidIP('256.1.1.1')).toBe(false);
  });

  it('should reject invalid IPs', () => {
    expect(isValidIP('not an ip')).toBe(false);
    expect(isValidIP('192.168.1')).toBe(false);
  });
});

describe('isPrivateIP', () => {
  it('should identify private ranges', () => {
    expect(isPrivateIP('10.0.0.1')).toBe(true);
    expect(isPrivateIP('172.16.0.1')).toBe(true);
    expect(isPrivateIP('192.168.1.1')).toBe(true);
    expect(isPrivateIP('127.0.0.1')).toBe(true);
  });

  it('should identify public IPs', () => {
    expect(isPrivateIP('8.8.8.8')).toBe(false);
    expect(isPrivateIP('1.1.1.1')).toBe(false);
  });
});

describe('maskSensitive', () => {
  it('should mask long strings', () => {
    const masked = maskSensitive('super_secret_password');
    expect(masked).toContain('****');
    expect(masked).not.toBe('super_secret_password');
  });

  it('should fully mask short strings', () => {
    expect(maskSensitive('abc')).toBe('****');
  });
});

describe('sanitizeOutput', () => {
  it('should redact AWS keys', () => {
    const output = sanitizeOutput('Key: AKIAIOSFODNN7EXAMPLE');
    expect(output).toContain('[REDACTED]');
    expect(output).not.toContain('AKIAIOSFODNN7EXAMPLE');
  });

  it('should redact GitHub tokens', () => {
    const output = sanitizeOutput('Token: ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx');
    expect(output).toContain('[REDACTED]');
  });

  it('should redact file paths', () => {
    const output = sanitizeOutput('Found at C:\\Users\\admin\\secrets.txt');
    expect(output).toContain('[REDACTED]');
  });

  it('should redact email addresses', () => {
    const output = sanitizeOutput('Contact: user@example.com');
    expect(output).toContain('[REDACTED]');
  });
});
