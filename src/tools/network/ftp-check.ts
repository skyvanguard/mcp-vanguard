import { z } from 'zod';
import * as net from 'net';
import { isInScope } from '../../config.js';

export const ftpCheckSchema = z.object({
  target: z.string().describe('Target IP or hostname'),
  port: z.number().default(21).describe('FTP port'),
  checkAnonymous: z.boolean().default(true).describe('Check for anonymous login'),
  timeout: z.number().default(10000).describe('Timeout in milliseconds')
});

export type FtpCheckInput = z.infer<typeof ftpCheckSchema>;

interface FtpCheckResult {
  banner: string | null;
  anonymousAllowed: boolean;
  ftpFeatures: string[];
  error?: string;
}

export async function ftpCheck(input: FtpCheckInput): Promise<{
  success: boolean;
  target: string;
  port: number;
  result: FtpCheckResult;
  error?: string;
}> {
  const { target, port, checkAnonymous, timeout } = input;

  if (!isInScope(target)) {
    return {
      success: false,
      target,
      port,
      result: { banner: null, anonymousAllowed: false, ftpFeatures: [] },
      error: `Target ${target} is not in scope. Use vanguard_set_scope first.`
    };
  }

  try {
    const result = await probeFtp(target, port, checkAnonymous, timeout);
    return { success: true, target, port, result };
  } catch (err) {
    return {
      success: false,
      target,
      port,
      result: { banner: null, anonymousAllowed: false, ftpFeatures: [] },
      error: err instanceof Error ? err.message : 'FTP check failed'
    };
  }
}

function probeFtp(host: string, port: number, checkAnon: boolean, timeout: number): Promise<FtpCheckResult> {
  return new Promise((resolve, reject) => {
    const socket = new net.Socket();
    let data = '';
    let banner: string | null = null;
    let anonymousAllowed = false;
    const features: string[] = [];
    let phase: 'banner' | 'user' | 'pass' | 'feat' | 'done' = 'banner';

    socket.setTimeout(timeout);

    socket.on('data', (chunk) => {
      data += chunk.toString();

      const lines = data.split('\r\n');
      data = lines.pop() || '';

      for (const line of lines) {
        const code = parseInt(line.substring(0, 3), 10);

        if (phase === 'banner' && (code === 220 || line.startsWith('220'))) {
          banner = line.replace(/^220[-\s]*/, '').trim();
          if (checkAnon) {
            socket.write('USER anonymous\r\n');
            phase = 'user';
          } else {
            socket.write('FEAT\r\n');
            phase = 'feat';
          }
        } else if (phase === 'user' && code === 331) {
          socket.write('PASS anonymous@\r\n');
          phase = 'pass';
        } else if (phase === 'user' && code === 530) {
          anonymousAllowed = false;
          socket.write('FEAT\r\n');
          phase = 'feat';
        } else if (phase === 'pass' && code === 230) {
          anonymousAllowed = true;
          socket.write('FEAT\r\n');
          phase = 'feat';
        } else if (phase === 'pass' && (code === 530 || code === 500)) {
          anonymousAllowed = false;
          socket.write('FEAT\r\n');
          phase = 'feat';
        } else if (phase === 'feat') {
          if (line.startsWith(' ')) {
            features.push(line.trim());
          }
          if (code === 211 && !line.startsWith('211-')) {
            socket.write('QUIT\r\n');
            phase = 'done';
          }
          if (code === 500 || code === 502) {
            socket.write('QUIT\r\n');
            phase = 'done';
          }
        } else if (phase === 'done') {
          socket.destroy();
        }
      }
    });

    socket.on('timeout', () => {
      socket.destroy();
      resolve({ banner, anonymousAllowed, ftpFeatures: features });
    });

    socket.on('close', () => {
      resolve({ banner, anonymousAllowed, ftpFeatures: features });
    });

    socket.on('error', (err) => {
      socket.destroy();
      reject(err);
    });

    socket.connect(port, host);
  });
}
