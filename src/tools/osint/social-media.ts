import { z } from 'zod';

export const socialMediaSchema = z.object({
  username: z.string().describe('Username to search across social media platforms'),
  platforms: z.array(z.enum([
    'github', 'twitter', 'linkedin', 'instagram', 'reddit',
    'facebook', 'tiktok', 'youtube', 'pinterest', 'medium'
  ])).default(['github', 'twitter', 'linkedin', 'instagram', 'reddit'])
    .describe('Platforms to check')
});

export type SocialMediaInput = z.infer<typeof socialMediaSchema>;

interface PlatformResult {
  platform: string;
  url: string;
  exists: boolean | null;
  statusCode?: number;
}

const PLATFORM_URLS: Record<string, string> = {
  github: 'https://github.com/{username}',
  twitter: 'https://x.com/{username}',
  linkedin: 'https://www.linkedin.com/in/{username}',
  instagram: 'https://www.instagram.com/{username}',
  reddit: 'https://www.reddit.com/user/{username}',
  facebook: 'https://www.facebook.com/{username}',
  tiktok: 'https://www.tiktok.com/@{username}',
  youtube: 'https://www.youtube.com/@{username}',
  pinterest: 'https://www.pinterest.com/{username}',
  medium: 'https://medium.com/@{username}'
};

export async function socialMedia(input: SocialMediaInput): Promise<{
  success: boolean;
  username: string;
  results: PlatformResult[];
  found: string[];
  error?: string;
}> {
  const { username, platforms } = input;

  const results = await Promise.all(
    platforms.map(platform => checkPlatform(username, platform))
  );

  const found = results.filter(r => r.exists === true).map(r => r.platform);

  return {
    success: true,
    username,
    results,
    found
  };
}

async function checkPlatform(username: string, platform: string): Promise<PlatformResult> {
  const urlTemplate = PLATFORM_URLS[platform];
  if (!urlTemplate) {
    return { platform, url: '', exists: null };
  }

  const url = urlTemplate.replace('{username}', encodeURIComponent(username));

  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 8000);

    const response = await fetch(url, {
      method: 'HEAD',
      headers: {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
      },
      redirect: 'follow',
      signal: controller.signal
    });
    clearTimeout(timer);

    return {
      platform,
      url,
      exists: response.status === 200,
      statusCode: response.status
    };
  } catch {
    return {
      platform,
      url,
      exists: null,
      statusCode: 0
    };
  }
}
