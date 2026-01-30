import { describe, it, expect } from 'vitest';
import {
  createSafeError,
  toSafeError,
  formatSafeError,
  ToolError,
  wrapError
} from '../src/utils/safe-error.js';

describe('createSafeError', () => {
  it('should create error with code and message', () => {
    const error = createSafeError('SCOPE_VIOLATION', 'test_tool');
    expect(error.code).toBe('SCOPE_VIOLATION');
    expect(error.message).toContain('authorized scope');
    expect(error.tool).toBe('test_tool');
  });

  it('should include sanitized details', () => {
    const error = createSafeError('INVALID_INPUT', 'test_tool', 'Bad parameter');
    expect(error.message).toContain('Bad parameter');
  });

  it('should include details in message', () => {
    const error = createSafeError('COMMAND_FAILED', 'test_tool', 'Process exited with code 1');
    expect(error.message).toContain('Process exited');
    expect(error.code).toBe('COMMAND_FAILED');
  });
});

describe('toSafeError', () => {
  it('should convert Error to SafeError', () => {
    const error = new Error('Connection timeout');
    const safe = toSafeError(error, 'http_client');

    expect(safe.code).toBe('TIMEOUT');
    expect(safe.tool).toBe('http_client');
  });

  it('should detect security errors', () => {
    const error = new Error('Security violation detected');
    error.name = 'SecurityError';
    const safe = toSafeError(error);

    expect(safe.code).toBe('SECURITY_ERROR');
  });

  it('should detect network errors', () => {
    const error = new Error('ENOTFOUND: DNS lookup failed');
    const safe = toSafeError(error);

    expect(safe.code).toBe('NETWORK_ERROR');
  });

  it('should detect scope violations', () => {
    const error = new Error('Target not in scope');
    const safe = toSafeError(error);

    expect(safe.code).toBe('SCOPE_VIOLATION');
  });

  it('should handle unknown errors', () => {
    const safe = toSafeError('not an error object');
    expect(safe.code).toBe('INTERNAL_ERROR');
  });

  it('should sanitize IP addresses in messages', () => {
    const error = new Error('Connection refused to 192.168.1.100:8080');
    const safe = toSafeError(error);

    expect(safe.message).toContain('[ip]');
    expect(safe.message).toContain('[port]');
    expect(safe.message).not.toContain('192.168.1.100');
  });

  it('should truncate long messages', () => {
    const longMessage = 'x'.repeat(500);
    const error = new Error(longMessage);
    const safe = toSafeError(error);

    expect(safe.message.length).toBeLessThanOrEqual(203); // 200 + '...'
  });

  it('should remove stack traces', () => {
    const error = new Error('Test error');
    error.stack = 'Error: Test error\n    at Object.<anonymous> (/path/to/file.ts:10:5)';
    const safe = toSafeError(error);

    expect(safe.message).not.toContain('Object.<anonymous>');
    expect(safe.message).not.toContain('/path/to/file.ts');
  });
});

describe('formatSafeError', () => {
  it('should format error as JSON', () => {
    const error = createSafeError('RATE_LIMITED', 'ffuf');
    const formatted = formatSafeError(error);

    const parsed = JSON.parse(formatted);
    expect(parsed.success).toBe(false);
    expect(parsed.error.code).toBe('RATE_LIMITED');
  });
});

describe('ToolError', () => {
  it('should create throwable error', () => {
    const error = new ToolError('PERMISSION_DENIED', 'file_access');

    expect(error).toBeInstanceOf(Error);
    expect(error.code).toBe('PERMISSION_DENIED');
    expect(error.tool).toBe('file_access');
    expect(error.name).toBe('ToolError');
  });

  it('should convert to SafeError', () => {
    const error = new ToolError('NOT_FOUND', 'dns_lookup', 'Domain not found');
    const safe = error.toSafeError();

    expect(safe.code).toBe('NOT_FOUND');
    expect(safe.message).toContain('not found');
    expect(safe.tool).toBe('dns_lookup');
  });
});

describe('wrapError', () => {
  it('should pass through successful results', async () => {
    const result = await wrapError(
      async () => 'success',
      'test_tool'
    );
    expect(result).toBe('success');
  });

  it('should convert errors to SafeError', async () => {
    await expect(
      wrapError(
        async () => { throw new Error('Test failure'); },
        'test_tool'
      )
    ).rejects.toMatchObject({
      code: expect.any(String),
      tool: 'test_tool'
    });
  });
});
