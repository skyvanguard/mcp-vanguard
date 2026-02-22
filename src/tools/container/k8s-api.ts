import { z } from 'zod';
import { isInScope } from '../../config.js';

export const k8sApiSchema = z.object({
  target: z.string().describe('Kubernetes API server URL (e.g., "https://10.0.0.1:6443" or "https://10.0.0.1:10250")'),
  timeout: z.number().default(10000).describe('Timeout in milliseconds'),
});

export type K8sApiInput = z.infer<typeof k8sApiSchema>;

interface K8sEndpointResult {
  endpoint: string;
  accessible: boolean;
  status?: number;
  data?: string;
}

const K8S_ENDPOINTS = [
  { path: '/version', desc: 'API version' },
  { path: '/api/v1/namespaces', desc: 'Namespaces' },
  { path: '/api/v1/pods', desc: 'All pods' },
  { path: '/api/v1/secrets', desc: 'All secrets' },
  { path: '/api/v1/configmaps', desc: 'ConfigMaps' },
  { path: '/apis', desc: 'API groups' },
  { path: '/healthz', desc: 'Health check' },
  { path: '/metrics', desc: 'Prometheus metrics' },
];

const KUBELET_ENDPOINTS = [
  { path: '/pods', desc: 'Running pods' },
  { path: '/runningpods/', desc: 'Running pods (alt)' },
  { path: '/metrics', desc: 'Kubelet metrics' },
  { path: '/spec/', desc: 'Node spec' },
];

export async function k8sApi(input: K8sApiInput): Promise<{
  success: boolean;
  target: string;
  type: 'api-server' | 'kubelet' | 'unknown';
  results: K8sEndpointResult[];
  exposed: boolean;
  risk: 'critical' | 'high' | 'medium' | 'none';
  error?: string;
}> {
  const { target, timeout } = input;

  let hostname: string;
  try {
    hostname = new URL(target).hostname;
  } catch {
    return { success: false, target, type: 'unknown', results: [], exposed: false, risk: 'none', error: 'Invalid URL' };
  }

  if (!isInScope(hostname)) {
    return { success: false, target, type: 'unknown', results: [], exposed: false, risk: 'none', error: `Target ${hostname} is not in scope.` };
  }

  // Detect if it's kubelet (10250) or API server
  const port = new URL(target).port;
  const isKubelet = port === '10250' || port === '10255';
  const endpoints = isKubelet ? KUBELET_ENDPOINTS : K8S_ENDPOINTS;

  const results: K8sEndpointResult[] = [];

  for (const ep of endpoints) {
    const url = `${target}${ep.path}`;
    try {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), timeout);

      const response = await fetch(url, {
        headers: { 'User-Agent': 'mcp-vanguard/2.0' },
        signal: controller.signal,
      });
      clearTimeout(timer);

      const body = await response.text();
      const accessible = response.status === 200;

      results.push({
        endpoint: ep.path,
        accessible,
        status: response.status,
        data: accessible ? body.slice(0, 300) : undefined,
      });
    } catch {
      results.push({ endpoint: ep.path, accessible: false });
    }
  }

  const exposed = results.some(r => r.accessible);
  const hasSecrets = results.some(r => r.endpoint.includes('secrets') && r.accessible);
  const hasPods = results.some(r => r.endpoint.includes('pods') && r.accessible);

  let risk: 'critical' | 'high' | 'medium' | 'none' = 'none';
  if (hasSecrets) risk = 'critical';
  else if (hasPods) risk = 'high';
  else if (exposed) risk = 'medium';

  return {
    success: true,
    target,
    type: isKubelet ? 'kubelet' : 'api-server',
    results,
    exposed,
    risk,
  };
}
