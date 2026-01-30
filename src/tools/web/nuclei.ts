import { z } from 'zod';
import { isInScope, getConfig } from '../../config.js';
import { executeWindows, checkCommandExists } from '../../executor/windows.js';
import { executeWSL, checkWSLCommandExists } from '../../executor/wsl.js';

export const nucleiSchema = z.object({
  target: z.string().describe('Target URL or file with list of URLs'),
  templates: z.array(z.string()).optional().describe('Specific template IDs or paths'),
  tags: z.array(z.string()).optional().describe('Filter templates by tags (e.g., cve, rce, sqli)'),
  severity: z.array(z.enum(['info', 'low', 'medium', 'high', 'critical'])).optional()
    .describe('Filter by severity level'),
  excludeTags: z.array(z.string()).optional().describe('Tags to exclude'),
  rateLimit: z.number().default(150).describe('Requests per second limit'),
  timeout: z.number().default(600000).describe('Timeout in milliseconds'),
  headers: z.record(z.string()).optional().describe('Custom headers')
});

export type NucleiInput = z.infer<typeof nucleiSchema>;

interface NucleiResult {
  templateId: string;
  templateName: string;
  severity: string;
  type: string;
  host: string;
  matchedAt: string;
  extractedResults?: string[];
  description?: string;
  reference?: string[];
  tags?: string[];
}

export async function nucleiScan(input: NucleiInput): Promise<{
  success: boolean;
  target: string;
  results: NucleiResult[];
  stats?: {
    templatesLoaded: number;
    hostsScanned: number;
    matchesFound: number;
    duration: number;
  };
  error?: string;
}> {
  const { target, timeout } = input;

  const targetHost = extractHost(target);
  if (!isInScope(targetHost)) {
    return {
      success: false,
      target,
      results: [],
      error: `Target ${targetHost} is not in scope. Use vanguard_set_scope to add it.`
    };
  }

  const nucleiAvailableWindows = await checkCommandExists('nuclei');

  if (nucleiAvailableWindows) {
    return runNucleiWindows(input);
  }

  const config = getConfig();
  if (config.wslEnabled) {
    const nucleiAvailableWSL = await checkWSLCommandExists('nuclei');
    if (nucleiAvailableWSL) {
      return runNucleiWSL(input);
    }
  }

  return {
    success: false,
    target,
    results: [],
    error: 'nuclei not found. Install it on Windows or WSL.'
  };
}

async function runNucleiWindows(input: NucleiInput): Promise<{
  success: boolean;
  target: string;
  results: NucleiResult[];
  stats?: {
    templatesLoaded: number;
    hostsScanned: number;
    matchesFound: number;
    duration: number;
  };
  error?: string;
}> {
  const args = buildNucleiArgs(input);

  const startTime = Date.now();
  const result = await executeWindows('nuclei', args, { timeout: input.timeout });

  const results = parseNucleiJsonlOutput(result.stdout);

  return {
    success: true,
    target: input.target,
    results,
    stats: {
      templatesLoaded: 0,
      hostsScanned: 1,
      matchesFound: results.length,
      duration: Date.now() - startTime
    }
  };
}

async function runNucleiWSL(input: NucleiInput): Promise<{
  success: boolean;
  target: string;
  results: NucleiResult[];
  stats?: {
    templatesLoaded: number;
    hostsScanned: number;
    matchesFound: number;
    duration: number;
  };
  error?: string;
}> {
  const args = buildNucleiArgs(input);

  const startTime = Date.now();
  const result = await executeWSL('nuclei', args, { timeout: input.timeout });

  const results = parseNucleiJsonlOutput(result.stdout);

  return {
    success: true,
    target: input.target,
    results,
    stats: {
      templatesLoaded: 0,
      hostsScanned: 1,
      matchesFound: results.length,
      duration: Date.now() - startTime
    }
  };
}

function buildNucleiArgs(input: NucleiInput): string[] {
  const {
    target,
    templates,
    tags,
    severity,
    excludeTags,
    rateLimit,
    headers
  } = input;

  const args = [
    '-target', target,
    '-jsonl',
    '-silent',
    '-rate-limit', rateLimit.toString(),
    '-no-color'
  ];

  if (templates && templates.length > 0) {
    for (const t of templates) {
      args.push('-t', t);
    }
  }

  if (tags && tags.length > 0) {
    args.push('-tags', tags.join(','));
  }

  if (severity && severity.length > 0) {
    args.push('-severity', severity.join(','));
  }

  if (excludeTags && excludeTags.length > 0) {
    args.push('-exclude-tags', excludeTags.join(','));
  }

  if (headers) {
    for (const [key, value] of Object.entries(headers)) {
      args.push('-H', `${key}: ${value}`);
    }
  }

  return args;
}

function parseNucleiJsonlOutput(output: string): NucleiResult[] {
  const results: NucleiResult[] = [];

  const lines = output.split('\n').filter(line => line.trim());

  for (const line of lines) {
    try {
      const data = JSON.parse(line) as {
        'template-id'?: string;
        info?: {
          name?: string;
          severity?: string;
          description?: string;
          reference?: string[];
          tags?: string[];
        };
        type?: string;
        host?: string;
        matched?: string;
        'matched-at'?: string;
        'extracted-results'?: string[];
      };

      if (data['template-id']) {
        results.push({
          templateId: data['template-id'],
          templateName: data.info?.name || data['template-id'],
          severity: data.info?.severity || 'unknown',
          type: data.type || 'unknown',
          host: data.host || '',
          matchedAt: data['matched-at'] || data.matched || '',
          extractedResults: data['extracted-results'],
          description: data.info?.description,
          reference: data.info?.reference,
          tags: data.info?.tags
        });
      }
    } catch {
      // Skip non-JSON lines
    }
  }

  return results;
}

function extractHost(url: string): string {
  try {
    const parsed = new URL(url);
    return parsed.hostname;
  } catch {
    const match = url.match(/https?:\/\/([^/:]+)/);
    return match ? match[1] : url;
  }
}
