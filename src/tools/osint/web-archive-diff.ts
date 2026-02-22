import { z } from 'zod';

export const webArchiveDiffSchema = z.object({
  url: z.string().describe('URL to check in the Wayback Machine'),
  fromDate: z.string().optional().describe('Start date (YYYYMMDD format, e.g., "20230101")'),
  toDate: z.string().optional().describe('End date (YYYYMMDD format)'),
  limit: z.number().default(20).describe('Maximum snapshots to return'),
  timeout: z.number().default(15000).describe('Timeout in milliseconds')
});

export type WebArchiveDiffInput = z.infer<typeof webArchiveDiffSchema>;

interface Snapshot {
  timestamp: string;
  url: string;
  archiveUrl: string;
  statusCode: string;
  mimeType: string;
  length?: string;
}

interface ArchiveAnalysis {
  firstSeen?: string;
  lastSeen?: string;
  totalSnapshots: number;
  statusCodes: Record<string, number>;
  mimeTypes: Record<string, number>;
}

export async function webArchiveDiff(input: WebArchiveDiffInput): Promise<{
  success: boolean;
  url: string;
  snapshots: Snapshot[];
  analysis: ArchiveAnalysis;
  error?: string;
}> {
  const { url, fromDate, toDate, limit, timeout } = input;

  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeout);

    // CDX API for snapshot listing
    const params = new URLSearchParams({
      url,
      output: 'json',
      fl: 'timestamp,original,statuscode,mimetype,length',
      limit: String(limit),
      ...(fromDate ? { from: fromDate } : {}),
      ...(toDate ? { to: toDate } : {})
    });

    const response = await fetch(
      `https://web.archive.org/cdx/search/cdx?${params.toString()}`,
      {
        headers: { 'User-Agent': 'mcp-vanguard/2.0' },
        signal: controller.signal
      }
    );
    clearTimeout(timer);

    if (!response.ok) {
      return {
        success: false,
        url,
        snapshots: [],
        analysis: emptyAnalysis(),
        error: `Wayback CDX API returned ${response.status}`
      };
    }

    const data = await response.json() as string[][];

    if (!data || data.length <= 1) {
      return {
        success: true,
        url,
        snapshots: [],
        analysis: emptyAnalysis(),
        error: 'No snapshots found for this URL'
      };
    }

    // Skip header row
    const rows = data.slice(1);
    const snapshots: Snapshot[] = rows.map(row => ({
      timestamp: row[0],
      url: row[1],
      archiveUrl: `https://web.archive.org/web/${row[0]}/${row[1]}`,
      statusCode: row[2],
      mimeType: row[3],
      length: row[4]
    }));

    // Analysis
    const statusCodes: Record<string, number> = {};
    const mimeTypes: Record<string, number> = {};

    for (const snap of snapshots) {
      statusCodes[snap.statusCode] = (statusCodes[snap.statusCode] || 0) + 1;
      mimeTypes[snap.mimeType] = (mimeTypes[snap.mimeType] || 0) + 1;
    }

    const analysis: ArchiveAnalysis = {
      firstSeen: snapshots.length > 0 ? formatTimestamp(snapshots[0].timestamp) : undefined,
      lastSeen: snapshots.length > 0 ? formatTimestamp(snapshots[snapshots.length - 1].timestamp) : undefined,
      totalSnapshots: snapshots.length,
      statusCodes,
      mimeTypes
    };

    return { success: true, url, snapshots, analysis };
  } catch (err) {
    return {
      success: false,
      url,
      snapshots: [],
      analysis: emptyAnalysis(),
      error: err instanceof Error ? err.message : 'Archive search failed'
    };
  }
}

function emptyAnalysis(): ArchiveAnalysis {
  return {
    totalSnapshots: 0,
    statusCodes: {},
    mimeTypes: {}
  };
}

function formatTimestamp(ts: string): string {
  if (ts.length >= 14) {
    return `${ts.slice(0, 4)}-${ts.slice(4, 6)}-${ts.slice(6, 8)} ${ts.slice(8, 10)}:${ts.slice(10, 12)}:${ts.slice(12, 14)}`;
  }
  return ts;
}
