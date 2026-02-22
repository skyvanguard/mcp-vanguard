import { z } from 'zod';

export const jwtDecodeSchema = z.object({
  token: z.string().describe('JWT token to decode'),
});

export type JwtDecodeInput = z.infer<typeof jwtDecodeSchema>;

interface JwtSecurityIssue {
  issue: string;
  severity: 'info' | 'low' | 'medium' | 'high' | 'critical';
  details: string;
}

export async function jwtDecode(input: JwtDecodeInput): Promise<{
  success: boolean;
  token: string;
  header: Record<string, unknown>;
  payload: Record<string, unknown>;
  signature: string;
  securityIssues: JwtSecurityIssue[];
  expired: boolean;
  expiresAt?: string;
  issuedAt?: string;
  error?: string;
}> {
  const { token } = input;
  const parts = token.split('.');

  if (parts.length !== 3) {
    return {
      success: false,
      token: token.slice(0, 20) + '...',
      header: {},
      payload: {},
      signature: '',
      securityIssues: [],
      expired: false,
      error: `Invalid JWT: expected 3 parts, got ${parts.length}`,
    };
  }

  let header: Record<string, unknown>;
  let payload: Record<string, unknown>;

  try {
    header = JSON.parse(base64UrlDecode(parts[0]));
  } catch {
    return {
      success: false, token: token.slice(0, 20) + '...', header: {}, payload: {},
      signature: '', securityIssues: [], expired: false, error: 'Invalid JWT header (not valid base64/JSON)',
    };
  }

  try {
    payload = JSON.parse(base64UrlDecode(parts[1]));
  } catch {
    return {
      success: false, token: token.slice(0, 20) + '...', header, payload: {},
      signature: '', securityIssues: [], expired: false, error: 'Invalid JWT payload (not valid base64/JSON)',
    };
  }

  const signature = parts[2];
  const issues: JwtSecurityIssue[] = [];

  // Check algorithm
  const alg = String(header.alg || '').toLowerCase();
  if (alg === 'none') {
    issues.push({
      issue: 'Algorithm "none"',
      severity: 'critical',
      details: 'Token uses "none" algorithm — signature is not verified. Anyone can forge tokens.',
    });
  } else if (alg === 'hs256' && header.alg === 'HS256') {
    issues.push({
      issue: 'HMAC-SHA256 algorithm',
      severity: 'info',
      details: 'Uses symmetric signing (HS256). Ensure secret is strong (>=256 bits).',
    });
  }

  // Check for algorithm confusion (RS→HS)
  if (header.jwk || header.jku) {
    issues.push({
      issue: 'JWK/JKU header present',
      severity: 'high',
      details: 'Token contains JWK/JKU header — potential key injection attack vector.',
    });
  }

  // Check kid injection
  if (header.kid && typeof header.kid === 'string') {
    if (header.kid.includes('/') || header.kid.includes('..') || header.kid.includes("'") || header.kid.includes(';')) {
      issues.push({
        issue: 'Suspicious kid parameter',
        severity: 'high',
        details: `kid contains path/injection chars: "${header.kid}"`,
      });
    }
  }

  // Check expiration
  const now = Math.floor(Date.now() / 1000);
  const exp = typeof payload.exp === 'number' ? payload.exp : undefined;
  const iat = typeof payload.iat === 'number' ? payload.iat : undefined;
  const nbf = typeof payload.nbf === 'number' ? payload.nbf : undefined;

  const expired = exp !== undefined && exp < now;

  if (!exp) {
    issues.push({
      issue: 'No expiration (exp) claim',
      severity: 'medium',
      details: 'Token never expires. Should set reasonable expiration.',
    });
  } else if (exp - (iat || now) > 86400 * 30) {
    issues.push({
      issue: 'Long-lived token',
      severity: 'low',
      details: `Token validity: ${Math.round((exp - (iat || now)) / 86400)} days. Consider shorter expiry.`,
    });
  }

  if (expired) {
    issues.push({
      issue: 'Token expired',
      severity: 'info',
      details: `Expired at ${new Date(exp! * 1000).toISOString()}`,
    });
  }

  // Check sensitive data in payload
  const sensitiveKeys = ['password', 'secret', 'ssn', 'credit_card', 'cc', 'pin'];
  for (const key of Object.keys(payload)) {
    if (sensitiveKeys.some(s => key.toLowerCase().includes(s))) {
      issues.push({
        issue: 'Sensitive data in payload',
        severity: 'high',
        details: `Payload contains potentially sensitive key: "${key}". JWT payloads are base64, NOT encrypted.`,
      });
    }
  }

  // Empty signature
  if (!signature || signature === '') {
    issues.push({
      issue: 'Empty signature',
      severity: 'critical',
      details: 'Token has no signature. It can be freely modified.',
    });
  }

  return {
    success: true,
    token: token.slice(0, 20) + '...',
    header,
    payload,
    signature: signature.slice(0, 20) + '...',
    securityIssues: issues,
    expired,
    expiresAt: exp ? new Date(exp * 1000).toISOString() : undefined,
    issuedAt: iat ? new Date(iat * 1000).toISOString() : undefined,
  };
}

function base64UrlDecode(str: string): string {
  let base64 = str.replace(/-/g, '+').replace(/_/g, '/');
  while (base64.length % 4) base64 += '=';
  return Buffer.from(base64, 'base64').toString('utf8');
}
