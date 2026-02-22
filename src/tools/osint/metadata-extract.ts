import { z } from 'zod';

export const metadataExtractSchema = z.object({
  url: z.string().describe('URL to extract metadata from (HTML page)'),
  timeout: z.number().default(15000).describe('Timeout in milliseconds')
});

export type MetadataExtractInput = z.infer<typeof metadataExtractSchema>;

interface PageMetadata {
  title?: string;
  description?: string;
  author?: string;
  generator?: string;
  keywords?: string[];
  ogTags: Record<string, string>;
  twitterTags: Record<string, string>;
  emails: string[];
  phones: string[];
  links: {
    internal: string[];
    external: string[];
    social: string[];
  };
  scripts: string[];
  technologies: string[];
  server?: string;
  poweredBy?: string;
}

export async function metadataExtract(input: MetadataExtractInput): Promise<{
  success: boolean;
  url: string;
  metadata: PageMetadata;
  error?: string;
}> {
  const { url, timeout } = input;

  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeout);

    const response = await fetch(url, {
      headers: {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        'Accept': 'text/html,application/xhtml+xml'
      },
      redirect: 'follow',
      signal: controller.signal
    });
    clearTimeout(timer);

    if (!response.ok) {
      return {
        success: false,
        url,
        metadata: emptyMetadata(),
        error: `HTTP ${response.status}`
      };
    }

    const html = await response.text();
    const headers = response.headers;

    const metadata = extractMetadata(html, url, headers);

    return { success: true, url, metadata };
  } catch (err) {
    return {
      success: false,
      url,
      metadata: emptyMetadata(),
      error: err instanceof Error ? err.message : 'Request failed'
    };
  }
}

function emptyMetadata(): PageMetadata {
  return {
    ogTags: {},
    twitterTags: {},
    emails: [],
    phones: [],
    links: { internal: [], external: [], social: [] },
    scripts: [],
    technologies: []
  };
}

function extractMetadata(html: string, baseUrl: string, headers: Headers): PageMetadata {
  const metadata = emptyMetadata();
  let hostname: string;
  try {
    hostname = new URL(baseUrl).hostname;
  } catch {
    hostname = '';
  }

  // Response headers
  metadata.server = headers.get('server') || undefined;
  metadata.poweredBy = headers.get('x-powered-by') || undefined;

  // Title
  const titleMatch = html.match(/<title[^>]*>([^<]+)<\/title>/i);
  if (titleMatch) metadata.title = titleMatch[1].trim();

  // Meta tags
  const metaPattern = /<meta\s+[^>]*>/gi;
  let metaMatch;
  while ((metaMatch = metaPattern.exec(html)) !== null) {
    const tag = metaMatch[0];
    const name = extractAttr(tag, 'name') || extractAttr(tag, 'property');
    const content = extractAttr(tag, 'content');

    if (!name || !content) continue;

    const lowerName = name.toLowerCase();

    if (lowerName === 'description') metadata.description = content;
    else if (lowerName === 'author') metadata.author = content;
    else if (lowerName === 'generator') metadata.generator = content;
    else if (lowerName === 'keywords') metadata.keywords = content.split(',').map(k => k.trim());
    else if (lowerName.startsWith('og:')) metadata.ogTags[lowerName] = content;
    else if (lowerName.startsWith('twitter:')) metadata.twitterTags[lowerName] = content;
  }

  // Emails
  const emailPattern = /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g;
  const emailMatches = html.match(emailPattern) || [];
  metadata.emails = [...new Set(emailMatches)].slice(0, 20);

  // Phone numbers
  const phonePattern = /(?:\+?1[-.\s]?)?(?:\(?\d{3}\)?[-.\s]?)?\d{3}[-.\s]?\d{4}/g;
  const phoneMatches = html.match(phonePattern) || [];
  metadata.phones = [...new Set(phoneMatches)].slice(0, 10);

  // Links
  const linkPattern = /href=["']([^"']+)["']/gi;
  const socialDomains = ['twitter.com', 'x.com', 'facebook.com', 'linkedin.com', 'instagram.com', 'github.com', 'youtube.com'];
  let linkMatch;
  const internalSet = new Set<string>();
  const externalSet = new Set<string>();
  const socialSet = new Set<string>();

  while ((linkMatch = linkPattern.exec(html)) !== null) {
    const href = linkMatch[1];
    if (href.startsWith('#') || href.startsWith('javascript:') || href.startsWith('mailto:')) continue;

    try {
      const resolved = new URL(href, baseUrl);
      const link = resolved.href;

      if (socialDomains.some(d => resolved.hostname.includes(d))) {
        socialSet.add(link);
      } else if (resolved.hostname === hostname) {
        internalSet.add(link);
      } else {
        externalSet.add(link);
      }
    } catch {
      // Invalid URL, skip
    }
  }

  metadata.links.internal = [...internalSet].slice(0, 30);
  metadata.links.external = [...externalSet].slice(0, 30);
  metadata.links.social = [...socialSet].slice(0, 10);

  // Script sources
  const scriptPattern = /src=["']([^"']+\.js[^"']*)["']/gi;
  let scriptMatch;
  while ((scriptMatch = scriptPattern.exec(html)) !== null) {
    metadata.scripts.push(scriptMatch[1]);
  }
  metadata.scripts = [...new Set(metadata.scripts)].slice(0, 20);

  // Technology hints
  if (metadata.generator) metadata.technologies.push(metadata.generator);
  if (html.includes('wp-content') || html.includes('wp-includes')) metadata.technologies.push('WordPress');
  if (html.includes('__next')) metadata.technologies.push('Next.js');
  if (html.includes('_nuxt')) metadata.technologies.push('Nuxt.js');
  if (html.includes('react')) metadata.technologies.push('React');
  if (html.includes('angular')) metadata.technologies.push('Angular');
  if (html.includes('vue')) metadata.technologies.push('Vue.js');
  if (html.includes('jquery') || html.includes('jQuery')) metadata.technologies.push('jQuery');
  if (html.includes('bootstrap')) metadata.technologies.push('Bootstrap');
  if (html.includes('tailwind')) metadata.technologies.push('Tailwind CSS');
  if (metadata.poweredBy) metadata.technologies.push(metadata.poweredBy);

  metadata.technologies = [...new Set(metadata.technologies)];

  return metadata;
}

function extractAttr(tag: string, attr: string): string | null {
  const pattern = new RegExp(`${attr}=["']([^"']+)["']`, 'i');
  const match = tag.match(pattern);
  return match ? match[1] : null;
}
