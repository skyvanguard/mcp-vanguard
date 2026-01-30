import { z } from 'zod';

export const paramMinerSchema = z.object({
  url: z.string().describe('Target URL to discover parameters'),
  wordlist: z.enum(['common', 'extended', 'custom']).default('common')
    .describe('Parameter wordlist to use'),
  customParams: z.array(z.string()).optional().describe('Custom parameters to test'),
  method: z.enum(['GET', 'POST', 'BOTH']).default('GET').describe('HTTP method'),
  threads: z.number().default(10).describe('Concurrent requests'),
  timeout: z.number().default(10000).describe('Request timeout in ms'),
  detectMethod: z.enum(['status', 'length', 'reflection', 'all']).default('all')
    .describe('Detection method')
});

export type ParamMinerInput = z.infer<typeof paramMinerSchema>;

interface FoundParameter {
  name: string;
  method: string;
  evidence: string;
  confidence: 'high' | 'medium' | 'low';
  reflected: boolean;
  affectsStatus: boolean;
  affectsLength: boolean;
  lengthDiff?: number;
}

const commonParams = [
  'id', 'page', 'q', 'search', 'query', 'name', 'user', 'username', 'email',
  'password', 'pass', 'token', 'key', 'api_key', 'apikey', 'auth', 'code',
  'redirect', 'url', 'next', 'return', 'returnUrl', 'callback', 'cb',
  'file', 'path', 'dir', 'folder', 'src', 'dest', 'source', 'target',
  'action', 'cmd', 'command', 'exec', 'do', 'func', 'function', 'method',
  'type', 'format', 'output', 'view', 'template', 'include', 'require',
  'lang', 'language', 'locale', 'country', 'region', 'timezone',
  'debug', 'test', 'dev', 'admin', 'mode', 'config', 'settings',
  'limit', 'offset', 'start', 'count', 'size', 'sort', 'order', 'filter',
  'category', 'tag', 'label', 'status', 'state', 'enabled', 'active',
  'from', 'to', 'date', 'time', 'year', 'month', 'day',
  'data', 'json', 'xml', 'content', 'body', 'text', 'message', 'msg',
  'ref', 'reference', 'referrer', 'origin', 'host', 'domain',
  '_', '__', 'v', 'ver', 'version', 'rev', 'revision',
  'csrf', 'nonce', '_token', 'authenticity_token', 'xsrf',
  'utm_source', 'utm_medium', 'utm_campaign', 'fbclid', 'gclid'
];

const extendedParams = [
  ...commonParams,
  'access', 'account', 'act', 'addr', 'address', 'ajax', 'all', 'amp',
  'api', 'app', 'application', 'arg', 'args', 'array', 'article',
  'async', 'attachment', 'attr', 'attribute', 'back', 'backup', 'base',
  'begin', 'benchmark', 'bin', 'binary', 'bit', 'blog', 'boolean', 'break',
  'browse', 'browser', 'buffer', 'build', 'bulk', 'button', 'buy', 'bypass',
  'cache', 'call', 'cancel', 'captcha', 'cart', 'case', 'catalog', 'chain',
  'change', 'channel', 'char', 'charset', 'check', 'checkout', 'child',
  'chunk', 'class', 'clean', 'clear', 'click', 'client', 'clone', 'close',
  'col', 'collection', 'color', 'column', 'com', 'comment', 'commit',
  'compare', 'complete', 'compress', 'compute', 'condition', 'confirm',
  'connect', 'connection', 'console', 'const', 'constraint', 'contact',
  'container', 'context', 'continue', 'control', 'controller', 'convert',
  'cookie', 'copy', 'core', 'cost', 'counter', 'create', 'credentials',
  'credit', 'cron', 'cross', 'css', 'current', 'cursor', 'custom', 'cut',
  'daemon', 'dashboard', 'database', 'db', 'dbname', 'default', 'define',
  'delay', 'delete', 'demo', 'deny', 'deploy', 'depth', 'desc', 'description',
  'design', 'desktop', 'destroy', 'detail', 'details', 'detect', 'develop',
  'device', 'dialog', 'diff', 'digest', 'direct', 'directory', 'disable',
  'disallow', 'disconnect', 'discount', 'display', 'distinct', 'dns', 'doc',
  'document', 'download', 'draft', 'drive', 'driver', 'drop', 'dump', 'duplicate'
];

export async function paramMiner(input: ParamMinerInput): Promise<{
  success: boolean;
  url: string;
  foundParams: FoundParameter[];
  stats: {
    tested: number;
    found: number;
    duration: number;
  };
  error?: string;
}> {
  const { url, wordlist, customParams, method, threads, timeout, detectMethod } = input;

  const startTime = Date.now();
  const foundParams: FoundParameter[] = [];

  let params: string[];
  if (customParams && customParams.length > 0) {
    params = customParams;
  } else {
    params = wordlist === 'extended' ? extendedParams : commonParams;
  }

  try {
    const baseline = await getBaseline(url, timeout);
    if (!baseline) {
      return {
        success: false,
        url,
        foundParams: [],
        stats: { tested: 0, found: 0, duration: 0 },
        error: 'Failed to establish baseline'
      };
    }

    const methods = method === 'BOTH' ? ['GET', 'POST'] : [method];

    for (const httpMethod of methods) {
      const batches = chunkArray(params, threads);

      for (const batch of batches) {
        const results = await Promise.all(
          batch.map(param => testParameter(url, param, httpMethod, baseline, timeout, detectMethod))
        );

        for (const result of results) {
          if (result) {
            foundParams.push(result);
          }
        }
      }
    }

    return {
      success: true,
      url,
      foundParams,
      stats: {
        tested: params.length * methods.length,
        found: foundParams.length,
        duration: Date.now() - startTime
      }
    };
  } catch (err) {
    return {
      success: false,
      url,
      foundParams,
      stats: {
        tested: 0,
        found: 0,
        duration: Date.now() - startTime
      },
      error: err instanceof Error ? err.message : 'Parameter mining failed'
    };
  }
}

interface Baseline {
  status: number;
  length: number;
  body: string;
}

async function getBaseline(url: string, timeout: number): Promise<Baseline | null> {
  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), timeout);

    const response = await fetch(url, {
      headers: { 'User-Agent': 'mcp-vanguard/1.0' },
      signal: controller.signal
    });

    clearTimeout(timeoutId);

    const body = await response.text();

    return {
      status: response.status,
      length: body.length,
      body
    };
  } catch {
    return null;
  }
}

async function testParameter(
  baseUrl: string,
  param: string,
  method: string,
  baseline: Baseline,
  timeout: number,
  detectMethod: string
): Promise<FoundParameter | null> {
  const testValue = `vanguard_${Math.random().toString(36).slice(2, 8)}`;

  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), timeout);

    let testUrl = baseUrl;
    let body: string | undefined;
    const headers: Record<string, string> = {
      'User-Agent': 'mcp-vanguard/1.0'
    };

    if (method === 'GET') {
      const separator = baseUrl.includes('?') ? '&' : '?';
      testUrl = `${baseUrl}${separator}${param}=${testValue}`;
    } else {
      headers['Content-Type'] = 'application/x-www-form-urlencoded';
      body = `${param}=${testValue}`;
    }

    const response = await fetch(testUrl, {
      method,
      headers,
      body,
      signal: controller.signal
    });

    clearTimeout(timeoutId);

    const responseBody = await response.text();

    const affectsStatus = response.status !== baseline.status;
    const lengthDiff = Math.abs(responseBody.length - baseline.length);
    const affectsLength = lengthDiff > 50;
    const reflected = responseBody.includes(testValue);

    let isFound = false;
    let confidence: 'high' | 'medium' | 'low' = 'low';
    const evidence: string[] = [];

    if (detectMethod === 'all' || detectMethod === 'reflection') {
      if (reflected) {
        isFound = true;
        confidence = 'high';
        evidence.push('Value reflected in response');
      }
    }

    if (detectMethod === 'all' || detectMethod === 'status') {
      if (affectsStatus) {
        isFound = true;
        confidence = confidence === 'high' ? 'high' : 'medium';
        evidence.push(`Status changed: ${baseline.status} -> ${response.status}`);
      }
    }

    if (detectMethod === 'all' || detectMethod === 'length') {
      if (affectsLength && lengthDiff > 200) {
        isFound = true;
        confidence = confidence === 'high' ? 'high' : 'medium';
        evidence.push(`Length changed by ${lengthDiff} bytes`);
      }
    }

    if (!isFound) return null;

    return {
      name: param,
      method,
      evidence: evidence.join('; '),
      confidence,
      reflected,
      affectsStatus,
      affectsLength,
      lengthDiff
    };
  } catch {
    return null;
  }
}

function chunkArray<T>(array: T[], size: number): T[][] {
  const chunks: T[][] = [];
  for (let i = 0; i < array.length; i += size) {
    chunks.push(array.slice(i, i + size));
  }
  return chunks;
}
