import { describe, it, expect } from 'vitest';
import { encodingDetect } from '../src/tools/analysis/encoding-detect.js';

describe('encodingDetect', () => {
  it('should detect base64 encoding', async () => {
    const result = await encodingDetect({ input: btoa('hello world'), maxLayers: 5 });
    expect(result.success).toBe(true);
    expect(result.layers.length).toBeGreaterThan(0);
    expect(result.layers.some(l => l.encoding.toLowerCase().includes('base64'))).toBe(true);
  });

  it('should detect URL encoding', async () => {
    const result = await encodingDetect({ input: '%3Cscript%3Ealert(1)%3C%2Fscript%3E', maxLayers: 5 });
    expect(result.success).toBe(true);
    expect(result.layers.some(l => l.encoding.toLowerCase().includes('url'))).toBe(true);
  });

  it('should detect hex encoding', async () => {
    const result = await encodingDetect({ input: '48656c6c6f', maxLayers: 5 });
    expect(result.success).toBe(true);
    expect(result.layers.some(l => l.encoding.toLowerCase().includes('hex'))).toBe(true);
  });

  it('should handle plain text (no encoding)', async () => {
    const result = await encodingDetect({ input: 'just plain text', maxLayers: 5 });
    expect(result.success).toBe(true);
  });

  it('should detect double base64 encoding', async () => {
    const inner = btoa('secret');
    const double = btoa(inner);
    const result = await encodingDetect({ input: double, maxLayers: 5 });
    expect(result.success).toBe(true);
    expect(result.layers.length).toBeGreaterThanOrEqual(2);
  });

  it('should respect maxLayers limit', async () => {
    const result = await encodingDetect({ input: btoa(btoa(btoa('deep'))), maxLayers: 1 });
    expect(result.success).toBe(true);
    expect(result.layers.length).toBeLessThanOrEqual(1);
  });
});
