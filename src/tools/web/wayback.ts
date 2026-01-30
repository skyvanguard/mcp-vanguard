import { z } from 'zod';

export const waybackSchema = z.object({
  domain: z.string().describe('Domain to search in Wayback Machine'),
  matchType: z.enum(['exact', 'prefix', 'host', 'domain']).default('domain')
    .describe('URL match type'),
  filter: z.string().optional().describe('Filter results (e.g., "statuscode:200")'),
  collapse: z.string().optional().describe('Collapse results (e.g., "urlkey")'),
  limit: z.number().default(1000).describe('Maximum number of results'),
  from: z.string().optional().describe('Start date (YYYYMMDD)'),
  to: z.string().optional().describe('End date (YYYYMMDD)')
});

export type WaybackInput = z.infer<typeof waybackSchema>;

interface WaybackUrl {
  url: string;
  timestamp: string;
  statusCode?: string;
  mimeType?: string;
  length?: string;
}

export async function waybackSearch(input: WaybackInput): Promise<{
  success: boolean;
  domain: string;
  urls: WaybackUrl[];
  uniqueUrls: string[];
  stats: {
    total: number;
    uniqueCount: number;
  };
  error?: string;
}> {
  const { domain, matchType, filter, collapse, limit, from, to } = input;

  try {
    const params = new URLSearchParams({
      url: domain,
      matchType,
      output: 'json',
      fl: 'original,timestamp,statuscode,mimetype,length',
      limit: limit.toString()
    });

    if (filter) {
      params.append('filter', filter);
    }

    if (collapse) {
      params.append('collapse', collapse);
    }

    if (from) {
      params.append('from', from);
    }

    if (to) {
      params.append('to', to);
    }

    const url = `https://web.archive.org/cdx/search/cdx?${params.toString()}`;

    const response = await fetch(url, {
      headers: {
        'User-Agent': 'mcp-vanguard/1.0'
      }
    });

    if (!response.ok) {
      return {
        success: false,
        domain,
        urls: [],
        uniqueUrls: [],
        stats: { total: 0, uniqueCount: 0 },
        error: `Wayback Machine returned ${response.status}`
      };
    }

    const data = await response.json() as string[][];

    if (!Array.isArray(data) || data.length === 0) {
      return {
        success: true,
        domain,
        urls: [],
        uniqueUrls: [],
        stats: { total: 0, uniqueCount: 0 }
      };
    }

    const headers = data[0];
    const rows = data.slice(1);

    const originalIdx = headers.indexOf('original');
    const timestampIdx = headers.indexOf('timestamp');
    const statusIdx = headers.indexOf('statuscode');
    const mimeIdx = headers.indexOf('mimetype');
    const lengthIdx = headers.indexOf('length');

    const urls: WaybackUrl[] = rows.map(row => ({
      url: row[originalIdx] || '',
      timestamp: row[timestampIdx] || '',
      statusCode: statusIdx >= 0 ? row[statusIdx] : undefined,
      mimeType: mimeIdx >= 0 ? row[mimeIdx] : undefined,
      length: lengthIdx >= 0 ? row[lengthIdx] : undefined
    }));

    const uniqueUrls = Array.from(new Set(urls.map(u => u.url)));

    return {
      success: true,
      domain,
      urls,
      uniqueUrls,
      stats: {
        total: urls.length,
        uniqueCount: uniqueUrls.length
      }
    };
  } catch (err) {
    return {
      success: false,
      domain,
      urls: [],
      uniqueUrls: [],
      stats: { total: 0, uniqueCount: 0 },
      error: err instanceof Error ? err.message : 'Request failed'
    };
  }
}

export async function getWaybackSnapshot(url: string, timestamp?: string): Promise<{
  success: boolean;
  available: boolean;
  archiveUrl?: string;
  timestamp?: string;
  error?: string;
}> {
  try {
    const apiUrl = timestamp
      ? `https://archive.org/wayback/available?url=${encodeURIComponent(url)}&timestamp=${timestamp}`
      : `https://archive.org/wayback/available?url=${encodeURIComponent(url)}`;

    const response = await fetch(apiUrl, {
      headers: {
        'User-Agent': 'mcp-vanguard/1.0'
      }
    });

    if (!response.ok) {
      return {
        success: false,
        available: false,
        error: `API returned ${response.status}`
      };
    }

    const data = await response.json() as {
      archived_snapshots?: {
        closest?: {
          available: boolean;
          url: string;
          timestamp: string;
          status: string;
        };
      };
    };

    if (data.archived_snapshots?.closest?.available) {
      return {
        success: true,
        available: true,
        archiveUrl: data.archived_snapshots.closest.url,
        timestamp: data.archived_snapshots.closest.timestamp
      };
    }

    return {
      success: true,
      available: false
    };
  } catch (err) {
    return {
      success: false,
      available: false,
      error: err instanceof Error ? err.message : 'Request failed'
    };
  }
}

export function extractInterestingUrls(urls: string[]): {
  apis: string[];
  admin: string[];
  configs: string[];
  backups: string[];
  uploads: string[];
  other: string[];
} {
  const result = {
    apis: [] as string[],
    admin: [] as string[],
    configs: [] as string[],
    backups: [] as string[],
    uploads: [] as string[],
    other: [] as string[]
  };

  const patterns = {
    apis: [/\/api\//, /\/v\d+\//, /\/graphql/, /\/rest\//, /\.json$/],
    admin: [/\/admin/, /\/dashboard/, /\/panel/, /\/manage/, /\/wp-admin/],
    configs: [/\.env/, /\.config/, /\.yml$/, /\.yaml$/, /\.xml$/, /\.ini$/, /web\.config/],
    backups: [/\.bak$/, /\.backup$/, /\.old$/, /\.sql$/, /\.dump$/, /\.tar/, /\.zip$/],
    uploads: [/\/upload/, /\/uploads/, /\/files\//, /\/media\//, /\/attachments/]
  };

  for (const url of urls) {
    let categorized = false;

    for (const [category, regexes] of Object.entries(patterns)) {
      if (regexes.some(r => r.test(url))) {
        (result as Record<string, string[]>)[category].push(url);
        categorized = true;
        break;
      }
    }

    if (!categorized && (
      url.includes('?') ||
      /\.(php|asp|aspx|jsp|cgi)$/i.test(url)
    )) {
      result.other.push(url);
    }
  }

  return result;
}
