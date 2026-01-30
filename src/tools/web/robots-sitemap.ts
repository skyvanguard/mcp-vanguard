import { z } from 'zod';

export const robotsSitemapSchema = z.object({
  url: z.string().describe('Base URL of the target website'),
  parseRobots: z.boolean().default(true).describe('Parse robots.txt'),
  parseSitemap: z.boolean().default(true).describe('Parse sitemap.xml'),
  followSitemapLinks: z.boolean().default(true).describe('Follow sitemap index links'),
  maxUrls: z.number().default(1000).describe('Maximum URLs to collect'),
  timeout: z.number().default(30000).describe('Request timeout in ms')
});

export type RobotsSitemapInput = z.infer<typeof robotsSitemapSchema>;

interface RobotsRule {
  userAgent: string;
  allow: string[];
  disallow: string[];
  crawlDelay?: number;
  sitemaps: string[];
}

interface SitemapUrl {
  loc: string;
  lastmod?: string;
  changefreq?: string;
  priority?: number;
}

interface InterestingPath {
  path: string;
  reason: string;
  source: 'robots' | 'sitemap';
}

export async function robotsSitemap(input: RobotsSitemapInput): Promise<{
  success: boolean;
  baseUrl: string;
  robots: {
    found: boolean;
    rules: RobotsRule[];
    sitemaps: string[];
  };
  sitemap: {
    found: boolean;
    urls: SitemapUrl[];
    totalUrls: number;
  };
  interestingPaths: InterestingPath[];
  error?: string;
}> {
  const { url, parseRobots, parseSitemap, followSitemapLinks, maxUrls, timeout } = input;

  const baseUrl = url.replace(/\/+$/, '');
  let robotsRules: RobotsRule[] = [];
  let robotsSitemaps: string[] = [];
  let robotsFound = false;
  let sitemapUrls: SitemapUrl[] = [];
  let sitemapFound = false;
  const interestingPaths: InterestingPath[] = [];

  try {
    if (parseRobots) {
      const robotsResult = await fetchRobots(baseUrl, timeout);
      if (robotsResult) {
        robotsFound = true;
        robotsRules = robotsResult.rules;
        robotsSitemaps = robotsResult.sitemaps;

        for (const rule of robotsRules) {
          for (const path of rule.disallow) {
            const interest = analyzeDisallowedPath(path);
            if (interest) {
              interestingPaths.push({
                path,
                reason: interest,
                source: 'robots'
              });
            }
          }
        }
      }
    }

    if (parseSitemap) {
      const sitemapSources = robotsSitemaps.length > 0
        ? robotsSitemaps
        : [`${baseUrl}/sitemap.xml`, `${baseUrl}/sitemap_index.xml`];

      for (const sitemapUrl of sitemapSources) {
        if (sitemapUrls.length >= maxUrls) break;

        const result = await fetchSitemap(sitemapUrl, followSitemapLinks, maxUrls - sitemapUrls.length, timeout);
        if (result.urls.length > 0) {
          sitemapFound = true;
          sitemapUrls.push(...result.urls);
        }
      }

      for (const sUrl of sitemapUrls) {
        const interest = analyzeUrl(sUrl.loc);
        if (interest) {
          interestingPaths.push({
            path: sUrl.loc,
            reason: interest,
            source: 'sitemap'
          });
        }
      }
    }

    return {
      success: true,
      baseUrl,
      robots: {
        found: robotsFound,
        rules: robotsRules,
        sitemaps: robotsSitemaps
      },
      sitemap: {
        found: sitemapFound,
        urls: sitemapUrls.slice(0, maxUrls),
        totalUrls: sitemapUrls.length
      },
      interestingPaths: interestingPaths.slice(0, 100)
    };
  } catch (err) {
    return {
      success: false,
      baseUrl,
      robots: { found: false, rules: [], sitemaps: [] },
      sitemap: { found: false, urls: [], totalUrls: 0 },
      interestingPaths: [],
      error: err instanceof Error ? err.message : 'Failed to parse robots/sitemap'
    };
  }
}

async function fetchRobots(baseUrl: string, timeout: number): Promise<{
  rules: RobotsRule[];
  sitemaps: string[];
} | null> {
  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), timeout);

    const response = await fetch(`${baseUrl}/robots.txt`, {
      headers: { 'User-Agent': 'mcp-vanguard/1.0' },
      signal: controller.signal
    });

    clearTimeout(timeoutId);

    if (!response.ok) return null;

    const text = await response.text();
    return parseRobotsText(text);
  } catch {
    return null;
  }
}

function parseRobotsText(text: string): { rules: RobotsRule[]; sitemaps: string[] } {
  const lines = text.split('\n').map(l => l.trim());
  const rules: RobotsRule[] = [];
  const sitemaps: string[] = [];

  let currentRule: RobotsRule | null = null;

  for (const line of lines) {
    if (line.startsWith('#') || line === '') continue;

    const colonIndex = line.indexOf(':');
    if (colonIndex === -1) continue;

    const directive = line.slice(0, colonIndex).trim().toLowerCase();
    const value = line.slice(colonIndex + 1).trim();

    if (directive === 'user-agent') {
      if (currentRule) rules.push(currentRule);
      currentRule = {
        userAgent: value,
        allow: [],
        disallow: [],
        sitemaps: []
      };
    } else if (currentRule) {
      switch (directive) {
        case 'allow':
          currentRule.allow.push(value);
          break;
        case 'disallow':
          if (value) currentRule.disallow.push(value);
          break;
        case 'crawl-delay':
          currentRule.crawlDelay = parseInt(value, 10);
          break;
        case 'sitemap':
          sitemaps.push(value);
          break;
      }
    } else if (directive === 'sitemap') {
      sitemaps.push(value);
    }
  }

  if (currentRule) rules.push(currentRule);

  return { rules, sitemaps };
}

async function fetchSitemap(
  url: string,
  followIndex: boolean,
  maxUrls: number,
  timeout: number
): Promise<{ urls: SitemapUrl[] }> {
  const urls: SitemapUrl[] = [];

  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), timeout);

    const response = await fetch(url, {
      headers: { 'User-Agent': 'mcp-vanguard/1.0' },
      signal: controller.signal
    });

    clearTimeout(timeoutId);

    if (!response.ok) return { urls };

    const text = await response.text();

    if (text.includes('<sitemapindex')) {
      if (followIndex) {
        const sitemapUrls = extractSitemapIndexUrls(text);
        for (const sitemapUrl of sitemapUrls.slice(0, 10)) {
          if (urls.length >= maxUrls) break;
          const result = await fetchSitemap(sitemapUrl, false, maxUrls - urls.length, timeout);
          urls.push(...result.urls);
        }
      }
    } else {
      const parsed = parseSitemapXml(text);
      urls.push(...parsed.slice(0, maxUrls));
    }
  } catch {
    // Ignore fetch errors
  }

  return { urls };
}

function extractSitemapIndexUrls(xml: string): string[] {
  const urls: string[] = [];
  const regex = /<loc>([^<]+)<\/loc>/gi;
  let match;
  while ((match = regex.exec(xml)) !== null) {
    urls.push(match[1].trim());
  }
  return urls;
}

function parseSitemapXml(xml: string): SitemapUrl[] {
  const urls: SitemapUrl[] = [];
  const urlRegex = /<url>([\s\S]*?)<\/url>/gi;
  let urlMatch;

  while ((urlMatch = urlRegex.exec(xml)) !== null) {
    const urlBlock = urlMatch[1];

    const locMatch = urlBlock.match(/<loc>([^<]+)<\/loc>/i);
    if (!locMatch) continue;

    const url: SitemapUrl = { loc: locMatch[1].trim() };

    const lastmodMatch = urlBlock.match(/<lastmod>([^<]+)<\/lastmod>/i);
    if (lastmodMatch) url.lastmod = lastmodMatch[1].trim();

    const changefreqMatch = urlBlock.match(/<changefreq>([^<]+)<\/changefreq>/i);
    if (changefreqMatch) url.changefreq = changefreqMatch[1].trim();

    const priorityMatch = urlBlock.match(/<priority>([^<]+)<\/priority>/i);
    if (priorityMatch) url.priority = parseFloat(priorityMatch[1].trim());

    urls.push(url);
  }

  return urls;
}

function analyzeDisallowedPath(path: string): string | null {
  const patterns: Array<{ regex: RegExp; reason: string }> = [
    { regex: /admin/i, reason: 'Admin panel' },
    { regex: /login|signin|auth/i, reason: 'Authentication endpoint' },
    { regex: /api/i, reason: 'API endpoint' },
    { regex: /backup|\.bak|\.sql/i, reason: 'Potential backup files' },
    { regex: /config|\.env|settings/i, reason: 'Configuration files' },
    { regex: /upload|files|media/i, reason: 'File upload directory' },
    { regex: /private|internal|secret/i, reason: 'Private/internal area' },
    { regex: /\.git|\.svn|\.hg/i, reason: 'Version control' },
    { regex: /phpinfo|info\.php/i, reason: 'PHP info disclosure' },
    { regex: /debug|test|staging/i, reason: 'Debug/test environment' },
    { regex: /cgi-bin/i, reason: 'CGI scripts' },
    { regex: /wp-admin|wp-includes/i, reason: 'WordPress admin' },
    { regex: /\.log$|logs\//i, reason: 'Log files' }
  ];

  for (const { regex, reason } of patterns) {
    if (regex.test(path)) return reason;
  }

  return null;
}

function analyzeUrl(url: string): string | null {
  const path = new URL(url).pathname;
  return analyzeDisallowedPath(path);
}
