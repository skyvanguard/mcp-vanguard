import { z } from 'zod';
import { getConfig } from '../../config.js';
import { executeWSL, checkWSLCommandExists } from '../../executor/wsl.js';

export const hashCrackSchema = z.object({
  hash: z.string().describe('Hash to crack'),
  format: z.string().optional().describe('John format (e.g., "raw-md5", "bcrypt"). Auto-detected if omitted.'),
  wordlist: z.string().default('/usr/share/wordlists/rockyou.txt').describe('Path to wordlist in WSL'),
  timeout: z.number().default(60000).describe('Timeout in milliseconds (default 60s)'),
});

export type HashCrackInput = z.infer<typeof hashCrackSchema>;

export async function hashCrack(input: HashCrackInput): Promise<{
  success: boolean;
  hash: string;
  cracked: boolean;
  password?: string;
  format?: string;
  error?: string;
}> {
  const { hash, format, wordlist, timeout } = input;
  const config = getConfig();

  if (!config.wslEnabled) {
    return { success: false, hash, cracked: false, error: 'WSL is not enabled. John the Ripper requires WSL.' };
  }

  const available = await checkWSLCommandExists('john');
  if (!available) {
    return { success: false, hash, cracked: false, error: 'John the Ripper not found in WSL. Install with: sudo apt install john' };
  }

  // Write hash to temp file
  const tmpFile = `/tmp/mcp-vanguard-hash-${Date.now()}`;
  await executeWSL('bash', ['-c', `echo '${hash.replace(/'/g, "\\'")}' > ${tmpFile}`], { timeout: 5000 });

  try {
    const args = ['--wordlist=' + wordlist];
    if (format) args.push(`--format=${format}`);
    args.push(tmpFile);

    const result = await executeWSL('john', args, { timeout });

    // Show cracked results
    const showResult = await executeWSL('john', ['--show', tmpFile], { timeout: 10000 });

    // Cleanup
    await executeWSL('rm', ['-f', tmpFile], { timeout: 5000 });

    // Parse result
    const showOutput = showResult.stdout || '';
    const crackedMatch = showOutput.match(/^(.+?):(.+?)$/m);

    if (crackedMatch) {
      return {
        success: true,
        hash,
        cracked: true,
        password: crackedMatch[2],
        format,
      };
    }

    // Check if john reported any status
    const stdout = result.stdout || '';
    if (stdout.includes('No password hashes loaded')) {
      return { success: false, hash, cracked: false, error: 'Invalid hash format. Try specifying --format.' };
    }

    return {
      success: true,
      hash,
      cracked: false,
      format,
      error: 'Password not found in wordlist',
    };
  } catch (err) {
    // Cleanup on error
    await executeWSL('rm', ['-f', tmpFile], { timeout: 5000 }).catch(() => {});
    return {
      success: false,
      hash,
      cracked: false,
      error: err instanceof Error ? err.message : 'Hash cracking failed',
    };
  }
}
