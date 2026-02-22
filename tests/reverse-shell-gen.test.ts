import { describe, it, expect } from 'vitest';
import { reverseShellGen } from '../src/tools/exploit/reverse-shell-gen.js';

describe('reverseShellGen', () => {
  it('should generate bash reverse shell with correct IP and port', async () => {
    const result = await reverseShellGen({ lhost: '10.0.0.1', lport: 4444, type: 'bash', encoding: 'raw' });
    expect(result.success).toBe(true);
    expect(result.payload).toContain('10.0.0.1');
    expect(result.payload).toContain('4444');
    expect(result.payload).toContain('/dev/tcp/');
    expect(result.type).toBe('bash');
    expect(result.listenerCommand).toBe('nc -lvnp 4444');
  });

  it('should generate python reverse shell', async () => {
    const result = await reverseShellGen({ lhost: '192.168.1.10', lport: 9001, type: 'python', encoding: 'raw' });
    expect(result.success).toBe(true);
    expect(result.payload).toContain('192.168.1.10');
    expect(result.payload).toContain('9001');
    expect(result.payload).toContain('socket');
    expect(result.payload).toContain('subprocess');
  });

  it('should generate powershell reverse shell', async () => {
    const result = await reverseShellGen({ lhost: '10.0.0.1', lport: 443, type: 'powershell', encoding: 'raw' });
    expect(result.success).toBe(true);
    expect(result.payload).toContain('TCPClient');
    expect(result.payload).toContain('10.0.0.1');
    expect(result.payload).toContain('443');
  });

  it('should encode payload as base64', async () => {
    const result = await reverseShellGen({ lhost: '10.0.0.1', lport: 4444, type: 'bash', encoding: 'base64' });
    expect(result.success).toBe(true);
    expect(result.encoding).toBe('base64');
    // Base64 should not contain shell-specific raw chars
    expect(result.payload).toMatch(/^[A-Za-z0-9+/=]+$/);
    // Decode and verify content
    const decoded = Buffer.from(result.payload, 'base64').toString();
    expect(decoded).toContain('10.0.0.1');
    expect(decoded).toContain('4444');
  });

  it('should encode payload as URL encoding', async () => {
    const result = await reverseShellGen({ lhost: '10.0.0.1', lport: 4444, type: 'bash', encoding: 'url' });
    expect(result.success).toBe(true);
    expect(result.encoding).toBe('url');
    const decoded = decodeURIComponent(result.payload);
    expect(decoded).toContain('10.0.0.1');
  });

  it('should generate all shell types without error', async () => {
    const types = ['bash', 'python', 'python3', 'perl', 'php', 'ruby', 'nc', 'ncat', 'powershell', 'java', 'node'] as const;
    for (const type of types) {
      const result = await reverseShellGen({ lhost: '10.0.0.1', lport: 4444, type, encoding: 'raw' });
      expect(result.success).toBe(true);
      expect(result.type).toBe(type);
      expect(result.payload.length).toBeGreaterThan(0);
      expect(result.payload).toContain('10.0.0.1');
    }
  });

  it('should use default port 4444', async () => {
    const result = await reverseShellGen({ lhost: '10.0.0.1', lport: 4444, type: 'bash', encoding: 'raw' });
    expect(result.lport).toBe(4444);
    expect(result.listenerCommand).toBe('nc -lvnp 4444');
  });
});
