import { describe, it, expect } from 'vitest';
import { googleDorks } from '../src/tools/osint/google-dorks.js';

describe('googleDorks', () => {
  it('should generate dorks for default categories', async () => {
    const result = await googleDorks({
      domain: 'example.com',
      categories: ['sensitive_files', 'login_pages', 'exposed_data', 'directories']
    });
    expect(result.success).toBe(true);
    expect(result.domain).toBe('example.com');
    expect(result.dorks.length).toBeGreaterThan(0);
    expect(result.totalDorks).toBe(result.dorks.length);
  });

  it('should replace {domain} in all dorks', async () => {
    const result = await googleDorks({
      domain: 'test.org',
      categories: ['sensitive_files']
    });
    for (const dork of result.dorks) {
      expect(dork.dork).toContain('test.org');
      expect(dork.dork).not.toContain('{domain}');
    }
  });

  it('should set correct categories', async () => {
    const result = await googleDorks({
      domain: 'example.com',
      categories: ['cloud_storage', 'api_endpoints']
    });
    const categories = new Set(result.dorks.map(d => d.category));
    expect(categories.has('cloud_storage')).toBe(true);
    expect(categories.has('api_endpoints')).toBe(true);
    expect(categories.has('sensitive_files')).toBe(false);
  });

  it('should assign risk levels', async () => {
    const result = await googleDorks({
      domain: 'example.com',
      categories: ['sensitive_files']
    });
    for (const dork of result.dorks) {
      expect(['low', 'medium', 'high']).toContain(dork.risk);
    }
  });

  it('should generate subdomains dorks', async () => {
    const result = await googleDorks({
      domain: 'example.com',
      categories: ['subdomains']
    });
    expect(result.dorks.length).toBeGreaterThan(0);
    expect(result.dorks[0].dork).toContain('site:');
  });
});
