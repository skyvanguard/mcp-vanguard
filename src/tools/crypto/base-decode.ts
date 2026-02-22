import { z } from 'zod';

export const baseDecodeSchema = z.object({
  input: z.string().describe('Encoded string to decode/encode'),
  operation: z.enum(['decode', 'encode', 'detect']).default('detect')
    .describe('"detect" auto-identifies and decodes, "decode"/"encode" use specified format'),
  format: z.enum(['base64', 'base64url', 'base32', 'hex', 'url', 'html', 'unicode'])
    .optional().describe('Encoding format (required for encode, auto-detected for decode)'),
});

export type BaseDecodeInput = z.infer<typeof baseDecodeSchema>;

interface DecodeResult {
  format: string;
  decoded: string;
  confidence: 'high' | 'medium' | 'low';
}

export async function baseDecode(input: BaseDecodeInput): Promise<{
  success: boolean;
  input: string;
  operation: string;
  results: DecodeResult[];
  encoded?: string;
  error?: string;
}> {
  const { input: inputStr, operation, format } = input;

  if (operation === 'encode') {
    if (!format) {
      return { success: false, input: inputStr, operation, results: [], error: 'Format required for encoding' };
    }
    const encoded = encodeAs(inputStr, format);
    return {
      success: true,
      input: inputStr,
      operation: 'encode',
      results: [{ format, decoded: inputStr, confidence: 'high' }],
      encoded,
    };
  }

  if (operation === 'decode' && format) {
    const decoded = decodeAs(inputStr, format);
    if (decoded === null) {
      return { success: false, input: inputStr, operation, results: [], error: `Failed to decode as ${format}` };
    }
    return {
      success: true,
      input: inputStr,
      operation: 'decode',
      results: [{ format, decoded, confidence: 'high' }],
    };
  }

  // Auto-detect mode
  const results: DecodeResult[] = [];

  // Try Base64
  if (/^[A-Za-z0-9+/]+=*$/.test(inputStr) && inputStr.length >= 4) {
    try {
      const decoded = Buffer.from(inputStr, 'base64').toString('utf8');
      if (isPrintable(decoded)) {
        results.push({ format: 'base64', decoded, confidence: inputStr.length % 4 === 0 ? 'high' : 'medium' });
      }
    } catch { /* not base64 */ }
  }

  // Try Base64URL
  if (/^[A-Za-z0-9_-]+=*$/.test(inputStr) && inputStr.length >= 4) {
    try {
      const decoded = Buffer.from(inputStr, 'base64url').toString('utf8');
      if (isPrintable(decoded) && !results.some(r => r.decoded === decoded)) {
        results.push({ format: 'base64url', decoded, confidence: 'medium' });
      }
    } catch { /* not base64url */ }
  }

  // Try Hex
  if (/^[0-9a-fA-F]+$/.test(inputStr) && inputStr.length % 2 === 0 && inputStr.length >= 2) {
    try {
      const decoded = Buffer.from(inputStr, 'hex').toString('utf8');
      if (isPrintable(decoded)) {
        results.push({ format: 'hex', decoded, confidence: inputStr.length > 4 ? 'medium' : 'low' });
      }
    } catch { /* not hex */ }
  }

  // Try URL decode
  if (inputStr.includes('%')) {
    try {
      const decoded = decodeURIComponent(inputStr);
      if (decoded !== inputStr) {
        results.push({ format: 'url', decoded, confidence: 'high' });
      }
    } catch { /* not url encoded */ }
  }

  // Try HTML entities
  if (inputStr.includes('&') && inputStr.includes(';')) {
    const decoded = decodeHtmlEntities(inputStr);
    if (decoded !== inputStr) {
      results.push({ format: 'html', decoded, confidence: 'high' });
    }
  }

  // Try Unicode escapes
  if (inputStr.includes('\\u') || inputStr.includes('\\x')) {
    const decoded = decodeUnicode(inputStr);
    if (decoded !== inputStr) {
      results.push({ format: 'unicode', decoded, confidence: 'high' });
    }
  }

  // Multi-layer detection
  if (results.length > 0) {
    const firstDecoded = results[0].decoded;
    // Check if first result is itself encoded
    if (/^[A-Za-z0-9+/]+=*$/.test(firstDecoded) && firstDecoded.length >= 4) {
      try {
        const double = Buffer.from(firstDecoded, 'base64').toString('utf8');
        if (isPrintable(double)) {
          results.push({ format: 'double-base64', decoded: double, confidence: 'medium' });
        }
      } catch { /* */ }
    }
  }

  if (results.length === 0) {
    results.push({ format: 'plaintext', decoded: inputStr, confidence: 'low' });
  }

  return {
    success: true,
    input: inputStr,
    operation: 'detect',
    results,
  };
}

function encodeAs(str: string, format: string): string {
  switch (format) {
    case 'base64': return Buffer.from(str).toString('base64');
    case 'base64url': return Buffer.from(str).toString('base64url');
    case 'hex': return Buffer.from(str).toString('hex');
    case 'url': return encodeURIComponent(str);
    case 'html': return str.replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c] || c));
    case 'unicode': return [...str].map(c => `\\u${c.charCodeAt(0).toString(16).padStart(4, '0')}`).join('');
    default: return str;
  }
}

function decodeAs(str: string, format: string): string | null {
  try {
    switch (format) {
      case 'base64': return Buffer.from(str, 'base64').toString('utf8');
      case 'base64url': return Buffer.from(str, 'base64url').toString('utf8');
      case 'hex': return Buffer.from(str, 'hex').toString('utf8');
      case 'url': return decodeURIComponent(str);
      case 'html': return decodeHtmlEntities(str);
      case 'unicode': return decodeUnicode(str);
      default: return null;
    }
  } catch {
    return null;
  }
}

function isPrintable(str: string): boolean {
  // eslint-disable-next-line no-control-regex
  return /^[\x20-\x7E\t\n\r]+$/.test(str) && str.length > 0;
}

function decodeHtmlEntities(str: string): string {
  const entities: Record<string, string> = {
    '&amp;': '&', '&lt;': '<', '&gt;': '>', '&quot;': '"',
    '&#39;': "'", '&apos;': "'", '&nbsp;': ' ',
  };
  let result = str;
  for (const [entity, char] of Object.entries(entities)) {
    result = result.replaceAll(entity, char);
  }
  // Numeric entities
  result = result.replace(/&#(\d+);/g, (_, n) => String.fromCharCode(parseInt(n)));
  result = result.replace(/&#x([0-9a-fA-F]+);/g, (_, n) => String.fromCharCode(parseInt(n, 16)));
  return result;
}

function decodeUnicode(str: string): string {
  return str
    .replace(/\\u([0-9a-fA-F]{4})/g, (_, hex) => String.fromCharCode(parseInt(hex, 16)))
    .replace(/\\x([0-9a-fA-F]{2})/g, (_, hex) => String.fromCharCode(parseInt(hex, 16)));
}
