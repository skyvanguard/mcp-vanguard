import { describe, it, expect } from 'vitest';
import { jwtDecode } from '../src/tools/crypto/jwt-decode.js';

// Test JWT: {"alg":"HS256","typ":"JWT"}.{"sub":"1234567890","name":"Test","iat":1516239022}
const TEST_JWT = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IlRlc3QiLCJpYXQiOjE1MTYyMzkwMjJ9.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c';

describe('jwtDecode', () => {
  it('should decode valid JWT header', async () => {
    const result = await jwtDecode({ token: TEST_JWT });
    expect(result.success).toBe(true);
    expect(result.header).toEqual({ alg: 'HS256', typ: 'JWT' });
  });

  it('should decode valid JWT payload', async () => {
    const result = await jwtDecode({ token: TEST_JWT });
    expect(result.payload.sub).toBe('1234567890');
    expect(result.payload.name).toBe('Test');
    expect(result.payload.iat).toBe(1516239022);
  });

  it('should detect missing expiration', async () => {
    const result = await jwtDecode({ token: TEST_JWT });
    const noExp = result.securityIssues.find(i => i.issue.includes('No expiration'));
    expect(noExp).toBeDefined();
    expect(noExp!.severity).toBe('medium');
  });

  it('should reject invalid JWT format', async () => {
    const result = await jwtDecode({ token: 'not.a.valid.jwt.token' });
    expect(result.success).toBe(false);
    expect(result.error).toContain('expected 3 parts');
  });

  it('should reject malformed base64', async () => {
    const result = await jwtDecode({ token: '!!!.@@@.###' });
    expect(result.success).toBe(false);
    expect(result.error).toContain('Invalid JWT header');
  });

  it('should detect none algorithm as critical', async () => {
    // {"alg":"none","typ":"JWT"}.{"sub":"admin"}
    const noneHeader = Buffer.from('{"alg":"none","typ":"JWT"}').toString('base64url');
    const payload = Buffer.from('{"sub":"admin"}').toString('base64url');
    const noneToken = `${noneHeader}.${payload}.`;

    const result = await jwtDecode({ token: noneToken });
    expect(result.success).toBe(true);
    const noneIssue = result.securityIssues.find(i => i.issue.includes('none'));
    expect(noneIssue).toBeDefined();
    expect(noneIssue!.severity).toBe('critical');
  });

  it('should detect empty signature as critical', async () => {
    const noneHeader = Buffer.from('{"alg":"none"}').toString('base64url');
    const payload = Buffer.from('{"sub":"admin"}').toString('base64url');
    const result = await jwtDecode({ token: `${noneHeader}.${payload}.` });
    expect(result.success).toBe(true);
    const emptyIssue = result.securityIssues.find(i => i.issue.includes('Empty signature'));
    expect(emptyIssue).toBeDefined();
    expect(emptyIssue!.severity).toBe('critical');
  });

  it('should truncate token in output', async () => {
    const result = await jwtDecode({ token: TEST_JWT });
    expect(result.token.endsWith('...')).toBe(true);
    expect(result.token.length).toBeLessThan(TEST_JWT.length);
  });
});
