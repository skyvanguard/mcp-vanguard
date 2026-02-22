import { z } from 'zod';

export const encodingDetectSchema = z.object({
  input: z.string().describe('String to analyze for encoding layers'),
  maxLayers: z.number().default(5).describe('Maximum decoding layers to attempt'),
});

export type EncodingDetectInput = z.infer<typeof encodingDetectSchema>;

interface EncodingLayer {
  layer: number;
  encoding: string;
  decoded: string;
  confidence: 'high' | 'medium' | 'low';
}

export async function encodingDetect(input: EncodingDetectInput): Promise<{
  success: boolean;
  input: string;
  layers: EncodingLayer[];
  finalDecoded: string;
  totalLayers: number;
}> {
  const { input: inputStr, maxLayers } = input;
  const layers: EncodingLayer[] = [];
  let current = inputStr;

  for (let i = 0; i < maxLayers; i++) {
    const result = tryDecode(current);
    if (!result) break;

    layers.push({
      layer: i + 1,
      encoding: result.encoding,
      decoded: result.decoded,
      confidence: result.confidence,
    });

    if (result.decoded === current) break; // No progress
    current = result.decoded;
  }

  return {
    success: true,
    input: inputStr.slice(0, 100),
    layers,
    finalDecoded: current,
    totalLayers: layers.length,
  };
}

function tryDecode(str: string): { encoding: string; decoded: string; confidence: 'high' | 'medium' | 'low' } | null {
  // URL encoding
  if (str.includes('%') && /%[0-9a-fA-F]{2}/.test(str)) {
    try {
      const decoded = decodeURIComponent(str);
      if (decoded !== str) return { encoding: 'URL', decoded, confidence: 'high' };
    } catch { /* */ }
  }

  // Double URL encoding
  if (str.includes('%25')) {
    try {
      const decoded = decodeURIComponent(str);
      if (decoded !== str) return { encoding: 'Double-URL', decoded, confidence: 'high' };
    } catch { /* */ }
  }

  // Base64
  if (/^[A-Za-z0-9+/]+=*$/.test(str) && str.length >= 4 && str.length % 4 === 0) {
    try {
      const decoded = Buffer.from(str, 'base64').toString('utf8');
      if (isPrintable(decoded) && decoded !== str) {
        return { encoding: 'Base64', decoded, confidence: str.length > 8 ? 'high' : 'medium' };
      }
    } catch { /* */ }
  }

  // Base64URL
  if (/^[A-Za-z0-9_-]+=*$/.test(str) && str.length >= 4) {
    try {
      const decoded = Buffer.from(str, 'base64url').toString('utf8');
      if (isPrintable(decoded) && decoded !== str) {
        return { encoding: 'Base64URL', decoded, confidence: 'medium' };
      }
    } catch { /* */ }
  }

  // Hex
  if (/^(0x)?[0-9a-fA-F]+$/.test(str) && str.length >= 4 && str.replace('0x', '').length % 2 === 0) {
    try {
      const hex = str.replace('0x', '');
      const decoded = Buffer.from(hex, 'hex').toString('utf8');
      if (isPrintable(decoded) && decoded !== str) {
        return { encoding: 'Hex', decoded, confidence: hex.length > 8 ? 'medium' : 'low' };
      }
    } catch { /* */ }
  }

  // HTML entities
  if (/&(?:#\d+|#x[0-9a-f]+|[a-z]+);/i.test(str)) {
    const decoded = str
      .replace(/&#(\d+);/g, (_, n) => String.fromCharCode(parseInt(n)))
      .replace(/&#x([0-9a-f]+);/gi, (_, n) => String.fromCharCode(parseInt(n, 16)))
      .replace(/&amp;/g, '&').replace(/&lt;/g, '<').replace(/&gt;/g, '>')
      .replace(/&quot;/g, '"').replace(/&apos;/g, "'");
    if (decoded !== str) return { encoding: 'HTML Entities', decoded, confidence: 'high' };
  }

  // Unicode escapes
  if (/\\u[0-9a-f]{4}/i.test(str)) {
    const decoded = str.replace(/\\u([0-9a-f]{4})/gi, (_, hex) =>
      String.fromCharCode(parseInt(hex, 16))
    );
    if (decoded !== str) return { encoding: 'Unicode Escape', decoded, confidence: 'high' };
  }

  return null;
}

function isPrintable(str: string): boolean {
  // eslint-disable-next-line no-control-regex
  return /^[\x20-\x7E\t\n\r]+$/.test(str) && str.length > 0;
}
