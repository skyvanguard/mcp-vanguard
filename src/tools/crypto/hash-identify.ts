import { z } from 'zod';

export const hashIdentifySchema = z.object({
  hash: z.string().describe('Hash string to identify'),
});

export type HashIdentifyInput = z.infer<typeof hashIdentifySchema>;

interface HashMatch {
  algorithm: string;
  confidence: 'high' | 'medium' | 'low';
  hashcat_mode?: number;
  john_format?: string;
}

const HASH_PATTERNS: Array<{
  regex: RegExp;
  algorithm: string;
  confidence: 'high' | 'medium' | 'low';
  hashcat_mode?: number;
  john_format?: string;
}> = [
  // MD5
  { regex: /^[a-f0-9]{32}$/i, algorithm: 'MD5', confidence: 'medium', hashcat_mode: 0, john_format: 'raw-md5' },
  // SHA-1
  { regex: /^[a-f0-9]{40}$/i, algorithm: 'SHA-1', confidence: 'medium', hashcat_mode: 100, john_format: 'raw-sha1' },
  // SHA-256
  { regex: /^[a-f0-9]{64}$/i, algorithm: 'SHA-256', confidence: 'medium', hashcat_mode: 1400, john_format: 'raw-sha256' },
  // SHA-512
  { regex: /^[a-f0-9]{128}$/i, algorithm: 'SHA-512', confidence: 'medium', hashcat_mode: 1700, john_format: 'raw-sha512' },
  // SHA-384
  { regex: /^[a-f0-9]{96}$/i, algorithm: 'SHA-384', confidence: 'medium', hashcat_mode: 10800 },
  // NTLM
  { regex: /^[a-f0-9]{32}$/i, algorithm: 'NTLM', confidence: 'low', hashcat_mode: 1000, john_format: 'nt' },
  // bcrypt
  { regex: /^\$2[aby]?\$\d{2}\$[./A-Za-z0-9]{53}$/, algorithm: 'bcrypt', confidence: 'high', hashcat_mode: 3200, john_format: 'bcrypt' },
  // MD5-crypt
  { regex: /^\$1\$[./A-Za-z0-9]{8}\$[./A-Za-z0-9]{22}$/, algorithm: 'MD5-crypt', confidence: 'high', hashcat_mode: 500, john_format: 'md5crypt' },
  // SHA-256-crypt
  { regex: /^\$5\$[./A-Za-z0-9]+\$[./A-Za-z0-9]{43}$/, algorithm: 'SHA-256-crypt', confidence: 'high', hashcat_mode: 7400, john_format: 'sha256crypt' },
  // SHA-512-crypt
  { regex: /^\$6\$[./A-Za-z0-9]+\$[./A-Za-z0-9]{86}$/, algorithm: 'SHA-512-crypt', confidence: 'high', hashcat_mode: 1800, john_format: 'sha512crypt' },
  // MySQL 4.1+
  { regex: /^\*[A-F0-9]{40}$/i, algorithm: 'MySQL 4.1+', confidence: 'high', hashcat_mode: 300, john_format: 'mysql-sha1' },
  // PostgreSQL MD5
  { regex: /^md5[a-f0-9]{32}$/i, algorithm: 'PostgreSQL MD5', confidence: 'high' },
  // Apache APR1
  { regex: /^\$apr1\$[./A-Za-z0-9]{8}\$[./A-Za-z0-9]{22}$/, algorithm: 'Apache APR1-MD5', confidence: 'high', hashcat_mode: 1600 },
  // LM Hash
  { regex: /^[a-f0-9]{32}$/i, algorithm: 'LM', confidence: 'low', hashcat_mode: 3000, john_format: 'lm' },
  // Django PBKDF2
  { regex: /^pbkdf2_sha256\$/, algorithm: 'Django PBKDF2-SHA256', confidence: 'high', hashcat_mode: 10000 },
  // Argon2
  { regex: /^\$argon2(id?|d)\$/, algorithm: 'Argon2', confidence: 'high' },
  // scrypt
  { regex: /^\$scrypt\$/, algorithm: 'scrypt', confidence: 'high' },
  // CRC32
  { regex: /^[a-f0-9]{8}$/i, algorithm: 'CRC32', confidence: 'low' },
  // Base64 (not a hash but commonly confused)
  { regex: /^[A-Za-z0-9+/]+=*$/, algorithm: 'Possibly Base64 (not a hash)', confidence: 'low' },
];

export async function hashIdentify(input: HashIdentifyInput): Promise<{
  success: boolean;
  hash: string;
  length: number;
  matches: HashMatch[];
  mostLikely?: string;
}> {
  const { hash } = input;
  const trimmed = hash.trim();
  const matches: HashMatch[] = [];

  for (const pattern of HASH_PATTERNS) {
    if (pattern.regex.test(trimmed)) {
      matches.push({
        algorithm: pattern.algorithm,
        confidence: pattern.confidence,
        hashcat_mode: pattern.hashcat_mode,
        john_format: pattern.john_format,
      });
    }
  }

  // Deduplicate by algorithm name
  const seen = new Set<string>();
  const unique = matches.filter(m => {
    if (seen.has(m.algorithm)) return false;
    seen.add(m.algorithm);
    return true;
  });

  // Sort: high confidence first
  unique.sort((a, b) => {
    const order = { high: 0, medium: 1, low: 2 };
    return order[a.confidence] - order[b.confidence];
  });

  return {
    success: true,
    hash: trimmed,
    length: trimmed.length,
    matches: unique,
    mostLikely: unique.find(m => m.confidence === 'high')?.algorithm
      || unique.find(m => m.confidence === 'medium')?.algorithm,
  };
}
