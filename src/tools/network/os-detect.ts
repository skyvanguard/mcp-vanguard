import { z } from 'zod';
import { isInScope, getConfig } from '../../config.js';
import { executeWSL, checkWSLCommandExists } from '../../executor/wsl.js';
import { executeWindows, checkCommandExists } from '../../executor/windows.js';

export const osDetectSchema = z.object({
  target: z.string().describe('Target IP or hostname'),
  timeout: z.number().default(300000).describe('Timeout in milliseconds')
});

export type OsDetectInput = z.infer<typeof osDetectSchema>;

interface OsGuess {
  name: string;
  accuracy: number;
  family?: string;
}

export async function osDetect(input: OsDetectInput): Promise<{
  success: boolean;
  target: string;
  osGuesses: OsGuess[];
  openPorts?: number[];
  error?: string;
}> {
  const { target, timeout } = input;

  if (!isInScope(target)) {
    return {
      success: false,
      target,
      osGuesses: [],
      error: `Target ${target} is not in scope. Use vanguard_set_scope first.`
    };
  }

  const config = getConfig();
  const args = ['-O', '--osscan-guess', target];

  // Try Windows nmap
  const nmapWindows = await checkCommandExists('nmap');
  if (nmapWindows) {
    const result = await executeWindows('nmap', args, { timeout });
    if (result.success || result.stdout) {
      return { success: true, target, ...parseOsOutput(result.stdout) };
    }
  }

  // Try WSL nmap
  if (config.wslEnabled) {
    const nmapWSL = await checkWSLCommandExists('nmap');
    if (nmapWSL) {
      const result = await executeWSL('nmap', args, { timeout });
      if (result.success || result.stdout) {
        return { success: true, target, ...parseOsOutput(result.stdout) };
      }
      return { success: false, target, osGuesses: [], error: result.stderr || 'OS detection failed' };
    }
  }

  return { success: false, target, osGuesses: [], error: 'nmap not available (OS detection requires nmap with root/admin)' };
}

function parseOsOutput(output: string): { osGuesses: OsGuess[]; openPorts?: number[] } {
  const osGuesses: OsGuess[] = [];
  const openPorts: number[] = [];

  // Parse OS guesses
  const osLines = output.match(/OS details?:.*|Aggressive OS guesses?:.*|Running:.*|OS CPE:.*/g) || [];
  for (const line of osLines) {
    if (line.startsWith('OS details:') || line.startsWith('Aggressive OS guesses:')) {
      const entries = line.replace(/^[^:]+:\s*/, '').split(',');
      for (const entry of entries) {
        const accMatch = entry.match(/\((\d+)%\)/);
        osGuesses.push({
          name: entry.replace(/\s*\(\d+%\)/, '').trim(),
          accuracy: accMatch ? parseInt(accMatch[1], 10) : 0
        });
      }
    } else if (line.startsWith('Running:')) {
      const family = line.replace('Running:', '').trim();
      if (osGuesses.length > 0) {
        osGuesses[0].family = family;
      }
    }
  }

  // Parse open ports
  const portMatches = output.matchAll(/(\d+)\/tcp\s+open/g);
  for (const m of portMatches) {
    openPorts.push(parseInt(m[1], 10));
  }

  return { osGuesses, openPorts: openPorts.length > 0 ? openPorts : undefined };
}
