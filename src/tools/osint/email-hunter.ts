import { z } from 'zod';
import { getConfig } from '../../config.js';

export const emailHunterSchema = z.object({
  domain: z.string().describe('Domain to search for email addresses'),
  limit: z.number().default(20).describe('Maximum results')
});

export type EmailHunterInput = z.infer<typeof emailHunterSchema>;

interface EmailResult {
  email: string;
  type?: string;
  confidence?: number;
  source?: string;
}

export async function emailHunter(input: EmailHunterInput): Promise<{
  success: boolean;
  domain: string;
  emails: EmailResult[];
  pattern?: string;
  error?: string;
}> {
  const { domain, limit } = input;
  const config = getConfig();

  // Try Hunter.io API if key available
  if (config.apiKeys.hunter) {
    try {
      const url = `https://api.hunter.io/v2/domain-search?domain=${encodeURIComponent(domain)}&limit=${limit}&api_key=${config.apiKeys.hunter}`;
      const response = await fetch(url, {
        headers: { 'User-Agent': 'mcp-vanguard/2.0' }
      });

      if (response.ok) {
        const data = await response.json() as {
          data: {
            pattern?: string;
            emails: Array<{
              value: string;
              type?: string;
              confidence?: number;
              sources?: Array<{ domain: string }>;
            }>;
          };
        };

        return {
          success: true,
          domain,
          emails: data.data.emails.map(e => ({
            email: e.value,
            type: e.type,
            confidence: e.confidence,
            source: e.sources?.[0]?.domain
          })),
          pattern: data.data.pattern
        };
      }
    } catch {
      // Fall through to passive methods
    }
  }

  // Passive: search common patterns and public sources
  const emails = await passiveEmailSearch(domain);

  return {
    success: true,
    domain,
    emails: emails.slice(0, limit),
    error: config.apiKeys.hunter ? undefined : 'No Hunter.io API key. Using passive methods only.'
  };
}

async function passiveEmailSearch(domain: string): Promise<EmailResult[]> {
  const emails: EmailResult[] = [];

  // Common email patterns to suggest
  const patterns = [
    'info', 'admin', 'contact', 'support', 'sales',
    'webmaster', 'postmaster', 'abuse', 'security'
  ];

  for (const prefix of patterns) {
    emails.push({
      email: `${prefix}@${domain}`,
      type: 'generic',
      confidence: 30,
      source: 'pattern_guess'
    });
  }

  // Try to find emails via Google cache / certificate data
  try {
    const crtUrl = `https://crt.sh/?q=%.${encodeURIComponent(domain)}&output=json`;
    const response = await fetch(crtUrl, {
      headers: { 'User-Agent': 'mcp-vanguard/2.0' }
    });

    if (response.ok) {
      const text = await response.text();
      const emailPattern = /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g;
      const found = text.match(emailPattern) || [];

      for (const email of [...new Set(found)]) {
        if (email.toLowerCase().endsWith(`@${domain}`) || email.toLowerCase().includes(domain)) {
          emails.push({
            email: email.toLowerCase(),
            type: 'personal',
            confidence: 60,
            source: 'crt.sh'
          });
        }
      }
    }
  } catch {
    // Silently continue
  }

  return emails;
}
