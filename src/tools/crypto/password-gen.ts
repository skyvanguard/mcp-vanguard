import { z } from 'zod';
import { randomBytes } from 'crypto';
import { getConfig } from '../../config.js';
import { executeWSL, checkWSLCommandExists } from '../../executor/wsl.js';

export const passwordGenSchema = z.object({
  mode: z.enum(['random', 'wordlist']).default('random')
    .describe('"random" for cryptographic generation, "wordlist" for CeWL-based targeted wordlist'),
  length: z.number().default(16).describe('Password length (random mode)'),
  count: z.number().default(10).describe('Number of passwords to generate'),
  charset: z.enum(['all', 'alpha', 'alphanum', 'hex']).default('all')
    .describe('Character set for random mode'),
  url: z.string().optional().describe('Target URL for CeWL wordlist generation'),
  minWordLength: z.number().default(6).describe('Minimum word length for CeWL'),
  depth: z.number().default(2).describe('Spider depth for CeWL'),
  timeout: z.number().default(30000).describe('Timeout for CeWL in milliseconds'),
});

export type PasswordGenInput = z.infer<typeof passwordGenSchema>;

const CHARSETS: Record<string, string> = {
  all: 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+-=[]{}|;:,.<>?',
  alpha: 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ',
  alphanum: 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789',
  hex: '0123456789abcdef',
};

export async function passwordGen(input: PasswordGenInput): Promise<{
  success: boolean;
  mode: string;
  passwords: string[];
  count: number;
  source?: string;
  error?: string;
}> {
  const { mode, length, count, charset, url, minWordLength, depth, timeout } = input;

  if (mode === 'random') {
    const chars = CHARSETS[charset] || CHARSETS.all;
    const passwords: string[] = [];

    for (let i = 0; i < count; i++) {
      passwords.push(generateSecurePassword(chars, length));
    }

    return {
      success: true,
      mode: 'random',
      passwords,
      count: passwords.length,
      source: `Cryptographic random (${charset}, ${length} chars)`,
    };
  }

  // Wordlist mode with CeWL
  if (!url) {
    return { success: false, mode: 'wordlist', passwords: [], count: 0, error: 'URL required for wordlist mode' };
  }

  const config = getConfig();
  if (!config.wslEnabled) {
    return { success: false, mode: 'wordlist', passwords: [], count: 0, error: 'WSL required for CeWL wordlist generation' };
  }

  const available = await checkWSLCommandExists('cewl');
  if (!available) {
    return { success: false, mode: 'wordlist', passwords: [], count: 0, error: 'CeWL not found in WSL. Install with: sudo apt install cewl' };
  }

  try {
    const args = ['-d', String(depth), '-m', String(minWordLength), '-c', url];
    const result = await executeWSL('cewl', args, { timeout });

    if (!result.success && !result.stdout) {
      return { success: false, mode: 'wordlist', passwords: [], count: 0, error: result.stderr || 'CeWL failed' };
    }

    const words = (result.stdout || '')
      .split('\n')
      .map(line => line.trim().split(',')[0]?.trim())
      .filter(w => w && w.length >= minWordLength)
      .slice(0, count);

    return {
      success: true,
      mode: 'wordlist',
      passwords: words,
      count: words.length,
      source: `CeWL spider (depth=${depth}, minLength=${minWordLength}) from ${url}`,
    };
  } catch (err) {
    return {
      success: false,
      mode: 'wordlist',
      passwords: [],
      count: 0,
      error: err instanceof Error ? err.message : 'CeWL wordlist generation failed',
    };
  }
}

function generateSecurePassword(charset: string, length: number): string {
  const bytes = randomBytes(length);
  let password = '';
  for (let i = 0; i < length; i++) {
    password += charset[bytes[i] % charset.length];
  }
  return password;
}
