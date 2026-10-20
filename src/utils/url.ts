/**
 * Extract the hostname from a URL for scope checks and reporting.
 *
 * Falls back to a regex when the URL cannot be parsed (e.g. missing scheme),
 * and tolerates the ffuf `FUZZ` placeholder by swapping it for a dummy token
 * so the URL stays parseable. Returns the original input as a last resort.
 */
export function extractHost(url: string): string {
  try {
    const parsed = new URL(url.replace('FUZZ', 'test'));
    return parsed.hostname;
  } catch {
    const match = url.match(/https?:\/\/([^/:]+)/);
    return match ? match[1] : url;
  }
}
