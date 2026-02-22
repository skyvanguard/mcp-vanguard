import { z } from 'zod';
import { isInScope } from '../../config.js';

export const httpMethodsSchema = z.object({
  url: z.string().describe('Target URL to test HTTP methods'),
  timeout: z.number().default(10000).describe('Timeout in milliseconds')
});

export type HttpMethodsInput = z.infer<typeof httpMethodsSchema>;

interface MethodResult {
  method: string;
  status: number;
  allowed: boolean;
  contentLength?: number;
  server?: string;
}

const METHODS_TO_TEST = [
  'GET', 'POST', 'PUT', 'DELETE', 'PATCH',
  'OPTIONS', 'HEAD', 'TRACE', 'CONNECT'
];

export async function httpMethods(input: HttpMethodsInput): Promise<{
  success: boolean;
  url: string;
  methods: MethodResult[];
  allowHeader?: string[];
  dangerousMethods: string[];
  error?: string;
}> {
  const { url, timeout } = input;

  // Extract hostname from URL for scope check
  let hostname: string;
  try {
    hostname = new URL(url).hostname;
  } catch {
    return {
      success: false,
      url,
      methods: [],
      dangerousMethods: [],
      error: 'Invalid URL format'
    };
  }

  if (!isInScope(hostname)) {
    return {
      success: false,
      url,
      methods: [],
      dangerousMethods: [],
      error: `Target ${hostname} is not in scope. Use vanguard_set_scope first.`
    };
  }

  const methods: MethodResult[] = [];
  let allowHeader: string[] | undefined;

  // First try OPTIONS to get Allow header
  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeout);

    const optRes = await fetch(url, {
      method: 'OPTIONS',
      headers: { 'User-Agent': 'mcp-vanguard/2.0' },
      signal: controller.signal
    });
    clearTimeout(timer);

    const allow = optRes.headers.get('allow');
    if (allow) {
      allowHeader = allow.split(',').map(m => m.trim());
    }
  } catch {
    // OPTIONS might not work, continue with individual tests
  }

  // Test each method
  for (const method of METHODS_TO_TEST) {
    try {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), timeout);

      const res = await fetch(url, {
        method,
        headers: { 'User-Agent': 'mcp-vanguard/2.0' },
        signal: controller.signal,
        redirect: 'manual'
      });
      clearTimeout(timer);

      methods.push({
        method,
        status: res.status,
        allowed: res.status !== 405 && res.status !== 501,
        contentLength: parseInt(res.headers.get('content-length') || '0', 10) || undefined,
        server: res.headers.get('server') || undefined
      });
    } catch {
      methods.push({
        method,
        status: 0,
        allowed: false
      });
    }
  }

  const dangerousMethods = methods
    .filter(m => m.allowed && ['PUT', 'DELETE', 'TRACE', 'CONNECT'].includes(m.method))
    .map(m => m.method);

  return {
    success: true,
    url,
    methods,
    allowHeader,
    dangerousMethods
  };
}
