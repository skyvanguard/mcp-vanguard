import { z } from 'zod';
import * as net from 'net';
import { isInScope } from '../../config.js';

export const bannerGrabSchema = z.object({
  target: z.string().describe('Target IP or hostname'),
  ports: z.array(z.number()).default([21, 22, 25, 80, 110, 143, 443, 3306, 3389])
    .describe('Ports to grab banners from'),
  timeout: z.number().default(5000).describe('Per-port timeout in milliseconds')
});

export type BannerGrabInput = z.infer<typeof bannerGrabSchema>;

interface BannerResult {
  port: number;
  banner: string | null;
  error?: string;
}

export async function bannerGrab(input: BannerGrabInput): Promise<{
  success: boolean;
  target: string;
  banners: BannerResult[];
  error?: string;
}> {
  const { target, ports, timeout } = input;

  if (!isInScope(target)) {
    return {
      success: false,
      target,
      banners: [],
      error: `Target ${target} is not in scope. Use vanguard_set_scope first.`
    };
  }

  const banners = await Promise.all(
    ports.map(port => grabBanner(target, port, timeout))
  );

  return {
    success: true,
    target,
    banners
  };
}

function grabBanner(host: string, port: number, timeout: number): Promise<BannerResult> {
  return new Promise((resolve) => {
    const socket = new net.Socket();
    let data = '';

    socket.setTimeout(timeout);

    socket.on('connect', () => {
      // Send a basic probe for HTTP ports
      if (port === 80 || port === 443 || port === 8080 || port === 8443) {
        socket.write(`HEAD / HTTP/1.0\r\nHost: ${host}\r\n\r\n`);
      }
    });

    socket.on('data', (chunk) => {
      data += chunk.toString();
      if (data.length > 1024) {
        socket.destroy();
      }
    });

    socket.on('timeout', () => {
      socket.destroy();
      resolve({
        port,
        banner: data.trim() || null,
        error: data ? undefined : 'timeout'
      });
    });

    socket.on('close', () => {
      resolve({
        port,
        banner: data.trim() || null
      });
    });

    socket.on('error', (err) => {
      socket.destroy();
      resolve({
        port,
        banner: null,
        error: err.message
      });
    });

    socket.connect(port, host);
  });
}
