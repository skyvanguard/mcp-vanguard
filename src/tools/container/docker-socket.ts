import { z } from 'zod';
import { isInScope } from '../../config.js';

export const dockerSocketSchema = z.object({
  target: z.string().describe('Target host:port to check for exposed Docker socket (e.g., "192.168.1.10:2375")'),
  timeout: z.number().default(10000).describe('Timeout in milliseconds'),
});

export type DockerSocketInput = z.infer<typeof dockerSocketSchema>;

interface DockerInfo {
  accessible: boolean;
  version?: string;
  containers?: number;
  images?: number;
  os?: string;
  architecture?: string;
  kernelVersion?: string;
  apiVersion?: string;
}

export async function dockerSocket(input: DockerSocketInput): Promise<{
  success: boolean;
  target: string;
  info: DockerInfo;
  containers?: Array<{ id: string; name: string; image: string; state: string }>;
  risk: 'critical' | 'high' | 'none';
  error?: string;
}> {
  const { target, timeout } = input;
  const hostname = target.split(':')[0];

  if (!isInScope(hostname)) {
    return { success: false, target, info: { accessible: false }, risk: 'none', error: `Target ${hostname} is not in scope.` };
  }

  const baseUrl = target.includes('://') ? target : `http://${target}`;

  // Check /version
  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeout);

    const versionResp = await fetch(`${baseUrl}/version`, {
      headers: { 'User-Agent': 'mcp-vanguard/2.0' },
      signal: controller.signal,
    });
    clearTimeout(timer);

    if (versionResp.status !== 200) {
      return { success: true, target, info: { accessible: false }, risk: 'none' };
    }

    const versionData = await versionResp.json() as Record<string, unknown>;

    const info: DockerInfo = {
      accessible: true,
      version: String(versionData.Version || ''),
      apiVersion: String(versionData.ApiVersion || ''),
      os: String(versionData.Os || ''),
      architecture: String(versionData.Arch || ''),
      kernelVersion: String(versionData.KernelVersion || ''),
    };

    // Get container list
    let containers: Array<{ id: string; name: string; image: string; state: string }> | undefined;
    try {
      const containersResp = await fetch(`${baseUrl}/containers/json?all=true`, {
        headers: { 'User-Agent': 'mcp-vanguard/2.0' },
        signal: AbortSignal.timeout(timeout),
      });
      if (containersResp.status === 200) {
        const data = await containersResp.json() as Array<{ Id: string; Names: string[]; Image: string; State: string }>;
        info.containers = data.length;
        containers = data.slice(0, 20).map(c => ({
          id: c.Id.slice(0, 12),
          name: (c.Names?.[0] || '').replace(/^\//, ''),
          image: c.Image,
          state: c.State,
        }));
      }
    } catch { /* */ }

    // Get image count
    try {
      const imagesResp = await fetch(`${baseUrl}/images/json`, {
        headers: { 'User-Agent': 'mcp-vanguard/2.0' },
        signal: AbortSignal.timeout(timeout),
      });
      if (imagesResp.status === 200) {
        const data = await imagesResp.json() as unknown[];
        info.images = data.length;
      }
    } catch { /* */ }

    return {
      success: true,
      target,
      info,
      containers,
      risk: 'critical',
    };
  } catch (err) {
    return {
      success: true,
      target,
      info: { accessible: false },
      risk: 'none',
      error: err instanceof Error ? err.message : 'Connection failed',
    };
  }
}
