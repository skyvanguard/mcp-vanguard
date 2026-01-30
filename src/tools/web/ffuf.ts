import { z } from 'zod';
import { isInScope } from '../../config.js';
import { executeWindows, checkCommandExists } from '../../executor/windows.js';
import { executeWSL, checkWSLCommandExists } from '../../executor/wsl.js';
import { getConfig } from '../../config.js';

export const ffufSchema = z.object({
  url: z.string().describe('Target URL with FUZZ keyword (e.g., https://example.com/FUZZ)'),
  wordlist: z.string().default('common').describe('Wordlist: common, big, directories, or custom path'),
  method: z.enum(['GET', 'POST', 'PUT', 'DELETE']).default('GET'),
  extensions: z.string().optional().describe('File extensions to add (e.g., "php,html,js")'),
  filterCodes: z.string().default('404').describe('HTTP status codes to filter out'),
  matchCodes: z.string().optional().describe('HTTP status codes to match'),
  threads: z.number().default(40).describe('Number of concurrent threads'),
  timeout: z.number().default(300000).describe('Timeout in milliseconds'),
  headers: z.record(z.string()).optional().describe('Custom headers'),
  data: z.string().optional().describe('POST data (use FUZZ keyword)')
});

export type FfufInput = z.infer<typeof ffufSchema>;

interface FfufResult {
  url: string;
  status: number;
  length: number;
  words: number;
  lines: number;
  redirectLocation?: string;
}

const builtinWordlists: Record<string, string> = {
  'common': '/usr/share/seclists/Discovery/Web-Content/common.txt',
  'big': '/usr/share/seclists/Discovery/Web-Content/big.txt',
  'directories': '/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt',
  'api': '/usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt'
};

export async function ffufScan(input: FfufInput): Promise<{
  success: boolean;
  url: string;
  results: FfufResult[];
  stats?: {
    requestsSent: number;
    duration: number;
  };
  error?: string;
}> {
  const {
    url,
    wordlist,
    method,
    extensions,
    filterCodes,
    matchCodes,
    threads,
    timeout,
    headers,
    data
  } = input;

  const urlHost = extractHost(url);
  if (!isInScope(urlHost)) {
    return {
      success: false,
      url,
      results: [],
      error: `Target ${urlHost} is not in scope. Use vanguard_set_scope to add it.`
    };
  }

  if (!url.includes('FUZZ')) {
    return {
      success: false,
      url,
      results: [],
      error: 'URL must contain FUZZ keyword for fuzzing position'
    };
  }

  const ffufAvailableWindows = await checkCommandExists('ffuf');

  if (ffufAvailableWindows) {
    return runFfufWindows(input);
  }

  const config = getConfig();
  if (config.wslEnabled) {
    const ffufAvailableWSL = await checkWSLCommandExists('ffuf');
    if (ffufAvailableWSL) {
      return runFfufWSL(input);
    }
  }

  return {
    success: false,
    url,
    results: [],
    error: 'ffuf not found. Install it on Windows or WSL.'
  };
}

async function runFfufWindows(input: FfufInput): Promise<{
  success: boolean;
  url: string;
  results: FfufResult[];
  stats?: { requestsSent: number; duration: number };
  error?: string;
}> {
  const args = buildFfufArgs(input, false);

  const startTime = Date.now();
  const result = await executeWindows('ffuf', args, { timeout: input.timeout });

  if (!result.success && !result.stdout) {
    return {
      success: false,
      url: input.url,
      results: [],
      error: result.stderr || 'ffuf execution failed'
    };
  }

  const { results, requestsSent } = parseFfufJsonOutput(result.stdout);

  return {
    success: true,
    url: input.url,
    results,
    stats: {
      requestsSent,
      duration: Date.now() - startTime
    }
  };
}

async function runFfufWSL(input: FfufInput): Promise<{
  success: boolean;
  url: string;
  results: FfufResult[];
  stats?: { requestsSent: number; duration: number };
  error?: string;
}> {
  const args = buildFfufArgs(input, true);

  const startTime = Date.now();
  const result = await executeWSL('ffuf', args, { timeout: input.timeout });

  if (!result.success && !result.stdout) {
    return {
      success: false,
      url: input.url,
      results: [],
      error: result.stderr || 'ffuf execution failed'
    };
  }

  const { results, requestsSent } = parseFfufJsonOutput(result.stdout);

  return {
    success: true,
    url: input.url,
    results,
    stats: {
      requestsSent,
      duration: Date.now() - startTime
    }
  };
}

function buildFfufArgs(input: FfufInput, isWSL: boolean): string[] {
  const {
    url,
    wordlist,
    method,
    extensions,
    filterCodes,
    matchCodes,
    threads,
    headers,
    data
  } = input;

  const wordlistPath = builtinWordlists[wordlist] || wordlist;

  const args = [
    '-u', url,
    '-w', wordlistPath,
    '-X', method,
    '-t', threads.toString(),
    '-o', '-',
    '-of', 'json',
    '-s'
  ];

  if (extensions) {
    args.push('-e', extensions);
  }

  if (filterCodes) {
    args.push('-fc', filterCodes);
  }

  if (matchCodes) {
    args.push('-mc', matchCodes);
  }

  if (headers) {
    for (const [key, value] of Object.entries(headers)) {
      args.push('-H', `${key}: ${value}`);
    }
  }

  if (data) {
    args.push('-d', data);
  }

  return args;
}

function parseFfufJsonOutput(output: string): {
  results: FfufResult[];
  requestsSent: number;
} {
  const results: FfufResult[] = [];
  let requestsSent = 0;

  try {
    const jsonStart = output.indexOf('{');
    const jsonEnd = output.lastIndexOf('}');

    if (jsonStart === -1 || jsonEnd === -1) {
      return { results, requestsSent };
    }

    const jsonStr = output.slice(jsonStart, jsonEnd + 1);
    const data = JSON.parse(jsonStr) as {
      results?: Array<{
        url: string;
        status: number;
        length: number;
        words: number;
        lines: number;
        redirectlocation?: string;
      }>;
      stats?: {
        numberOfRequests: number;
      };
    };

    if (data.results) {
      for (const r of data.results) {
        results.push({
          url: r.url,
          status: r.status,
          length: r.length,
          words: r.words,
          lines: r.lines,
          redirectLocation: r.redirectlocation
        });
      }
    }

    if (data.stats) {
      requestsSent = data.stats.numberOfRequests;
    }
  } catch {
    // Failed to parse JSON
  }

  return { results, requestsSent };
}

function extractHost(url: string): string {
  try {
    const parsed = new URL(url.replace('FUZZ', 'test'));
    return parsed.hostname;
  } catch {
    const match = url.match(/https?:\/\/([^/:]+)/);
    return match ? match[1] : url;
  }
}
