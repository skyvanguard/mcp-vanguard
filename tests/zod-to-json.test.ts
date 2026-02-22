import { describe, it, expect } from 'vitest';
import { z } from 'zod';
import { zodToJsonSchema } from '../src/utils/zod-to-json.js';

describe('zodToJsonSchema', () => {
  it('should convert string fields', () => {
    const schema = z.object({
      name: z.string().describe('A name field')
    });
    const result = zodToJsonSchema(schema);
    expect(result.type).toBe('object');
    expect((result.properties as Record<string, Record<string, unknown>>).name.type).toBe('string');
    expect((result.properties as Record<string, Record<string, unknown>>).name.description).toBe('A name field');
    expect(result.required).toEqual(['name']);
  });

  it('should convert number fields', () => {
    const schema = z.object({
      count: z.number().describe('A count')
    });
    const result = zodToJsonSchema(schema);
    expect((result.properties as Record<string, Record<string, unknown>>).count.type).toBe('number');
  });

  it('should convert boolean fields', () => {
    const schema = z.object({
      active: z.boolean().describe('Is active')
    });
    const result = zodToJsonSchema(schema);
    expect((result.properties as Record<string, Record<string, unknown>>).active.type).toBe('boolean');
  });

  it('should convert enum fields', () => {
    const schema = z.object({
      mode: z.enum(['fast', 'slow']).describe('Mode')
    });
    const result = zodToJsonSchema(schema);
    const mode = (result.properties as Record<string, Record<string, unknown>>).mode;
    expect(mode.type).toBe('string');
    expect(mode.enum).toEqual(['fast', 'slow']);
  });

  it('should convert array of strings', () => {
    const schema = z.object({
      tags: z.array(z.string()).describe('Tags')
    });
    const result = zodToJsonSchema(schema);
    const tags = (result.properties as Record<string, Record<string, unknown>>).tags;
    expect(tags.type).toBe('array');
    expect(tags.items).toEqual({ type: 'string' });
  });

  it('should handle optional fields', () => {
    const schema = z.object({
      required: z.string(),
      optional: z.string().optional()
    });
    const result = zodToJsonSchema(schema);
    expect(result.required).toEqual(['required']);
  });

  it('should handle default values', () => {
    const schema = z.object({
      timeout: z.number().default(5000).describe('Timeout')
    });
    const result = zodToJsonSchema(schema);
    const timeout = (result.properties as Record<string, Record<string, unknown>>).timeout;
    expect(timeout.type).toBe('number');
    expect(timeout.default).toBe(5000);
  });

  it('should handle record type', () => {
    const schema = z.object({
      headers: z.record(z.string()).optional()
    });
    const result = zodToJsonSchema(schema);
    const headers = (result.properties as Record<string, Record<string, unknown>>).headers;
    expect(headers.type).toBe('object');
  });

  it('should handle complex schemas like port-scan', () => {
    const portScanSchema = z.object({
      target: z.string().describe('Target'),
      ports: z.string().default('1-1000').describe('Port range'),
      scanType: z.enum(['tcp', 'syn', 'udp']).default('tcp').describe('Scan type'),
      timeout: z.number().default(300000).describe('Timeout')
    });
    const result = zodToJsonSchema(portScanSchema);
    expect(result.required).toEqual(['target']);
    const props = result.properties as Record<string, Record<string, unknown>>;
    expect(props.target.type).toBe('string');
    expect(props.ports.default).toBe('1-1000');
    expect(props.scanType.enum).toEqual(['tcp', 'syn', 'udp']);
    expect(props.timeout.default).toBe(300000);
  });

  it('should handle array with enum items and default', () => {
    const schema = z.object({
      recordTypes: z.array(z.enum(['A', 'AAAA', 'MX']))
        .default(['A', 'AAAA'])
        .describe('DNS record types')
    });
    const result = zodToJsonSchema(schema);
    const recordTypes = (result.properties as Record<string, Record<string, unknown>>).recordTypes;
    expect(recordTypes.type).toBe('array');
    expect((recordTypes.items as Record<string, unknown>).enum).toEqual(['A', 'AAAA', 'MX']);
  });
});
