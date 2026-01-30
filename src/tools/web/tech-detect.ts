import { z } from 'zod';

export const techDetectSchema = z.object({
  url: z.string().describe('Target URL to detect technologies'),
  timeout: z.number().default(30000).describe('Request timeout in milliseconds')
});

export type TechDetectInput = z.infer<typeof techDetectSchema>;

interface Technology {
  name: string;
  category: string;
  version?: string;
  confidence: number;
  website?: string;
}

interface TechPattern {
  name: string;
  category: string;
  website?: string;
  patterns: {
    headers?: Record<string, RegExp>;
    html?: RegExp[];
    scripts?: RegExp[];
    meta?: Record<string, RegExp>;
    cookies?: Record<string, RegExp>;
  };
  versionPatterns?: RegExp[];
}

const techPatterns: TechPattern[] = [
  {
    name: 'Nginx',
    category: 'Web Server',
    website: 'https://nginx.org',
    patterns: {
      headers: { 'server': /nginx/i }
    },
    versionPatterns: [/nginx\/([0-9.]+)/i]
  },
  {
    name: 'Apache',
    category: 'Web Server',
    website: 'https://httpd.apache.org',
    patterns: {
      headers: { 'server': /apache/i }
    },
    versionPatterns: [/Apache\/([0-9.]+)/i]
  },
  {
    name: 'Cloudflare',
    category: 'CDN',
    website: 'https://cloudflare.com',
    patterns: {
      headers: {
        'server': /cloudflare/i,
        'cf-ray': /.*/
      }
    }
  },
  {
    name: 'AWS CloudFront',
    category: 'CDN',
    website: 'https://aws.amazon.com/cloudfront',
    patterns: {
      headers: {
        'x-amz-cf-id': /.*/,
        'x-amz-cf-pop': /.*/
      }
    }
  },
  {
    name: 'React',
    category: 'JavaScript Framework',
    website: 'https://reactjs.org',
    patterns: {
      html: [/data-reactroot/i, /__NEXT_DATA__/],
      scripts: [/react\.production\.min\.js/, /react-dom/]
    }
  },
  {
    name: 'Vue.js',
    category: 'JavaScript Framework',
    website: 'https://vuejs.org',
    patterns: {
      html: [/data-v-[a-f0-9]+/, /id="__nuxt"/],
      scripts: [/vue\.min\.js/, /vue\.runtime/]
    }
  },
  {
    name: 'Angular',
    category: 'JavaScript Framework',
    website: 'https://angular.io',
    patterns: {
      html: [/ng-version/, /_ngcontent-/, /ng-app/],
      scripts: [/angular\.min\.js/, /@angular\/core/]
    }
  },
  {
    name: 'jQuery',
    category: 'JavaScript Library',
    website: 'https://jquery.com',
    patterns: {
      scripts: [/jquery[.-]?(\d+\.?\d*\.?\d*)?\.min\.js/i, /jquery\.js/i]
    },
    versionPatterns: [/jquery[.-]?(\d+\.\d+\.?\d*)/i]
  },
  {
    name: 'Bootstrap',
    category: 'CSS Framework',
    website: 'https://getbootstrap.com',
    patterns: {
      html: [/class="[^"]*\b(container|row|col-)\b/],
      scripts: [/bootstrap\.min\.js/, /bootstrap\.bundle/]
    }
  },
  {
    name: 'Tailwind CSS',
    category: 'CSS Framework',
    website: 'https://tailwindcss.com',
    patterns: {
      html: [/class="[^"]*\b(flex|grid|p-\d|m-\d|text-|bg-|border-)\b/]
    }
  },
  {
    name: 'WordPress',
    category: 'CMS',
    website: 'https://wordpress.org',
    patterns: {
      html: [/wp-content/, /wp-includes/, /wp-json/],
      meta: { 'generator': /WordPress/i }
    },
    versionPatterns: [/WordPress\s+([0-9.]+)/i]
  },
  {
    name: 'Drupal',
    category: 'CMS',
    website: 'https://drupal.org',
    patterns: {
      html: [/Drupal\.settings/, /sites\/default\/files/],
      headers: { 'x-drupal-cache': /.*/ }
    }
  },
  {
    name: 'Joomla',
    category: 'CMS',
    website: 'https://joomla.org',
    patterns: {
      html: [/\/media\/jui\//, /\/components\/com_/],
      meta: { 'generator': /Joomla/i }
    }
  },
  {
    name: 'Shopify',
    category: 'E-commerce',
    website: 'https://shopify.com',
    patterns: {
      html: [/cdn\.shopify\.com/, /Shopify\.theme/],
      headers: { 'x-shopify-stage': /.*/ }
    }
  },
  {
    name: 'WooCommerce',
    category: 'E-commerce',
    website: 'https://woocommerce.com',
    patterns: {
      html: [/woocommerce/, /wc-block/]
    }
  },
  {
    name: 'PHP',
    category: 'Programming Language',
    website: 'https://php.net',
    patterns: {
      headers: { 'x-powered-by': /PHP/i }
    },
    versionPatterns: [/PHP\/([0-9.]+)/i]
  },
  {
    name: 'ASP.NET',
    category: 'Programming Language',
    website: 'https://dotnet.microsoft.com',
    patterns: {
      headers: {
        'x-powered-by': /ASP\.NET/i,
        'x-aspnet-version': /.*/
      }
    }
  },
  {
    name: 'Node.js',
    category: 'Programming Language',
    website: 'https://nodejs.org',
    patterns: {
      headers: { 'x-powered-by': /Express/i }
    }
  },
  {
    name: 'Google Analytics',
    category: 'Analytics',
    website: 'https://analytics.google.com',
    patterns: {
      html: [/google-analytics\.com\/analytics/, /gtag\(/, /UA-\d+-\d+/, /G-[A-Z0-9]+/],
      scripts: [/googletagmanager\.com/]
    }
  },
  {
    name: 'Google Tag Manager',
    category: 'Tag Manager',
    website: 'https://tagmanager.google.com',
    patterns: {
      html: [/googletagmanager\.com\/gtm\.js/, /GTM-[A-Z0-9]+/]
    }
  },
  {
    name: 'Varnish',
    category: 'Cache',
    website: 'https://varnish-cache.org',
    patterns: {
      headers: {
        'x-varnish': /.*/,
        'via': /varnish/i
      }
    }
  },
  {
    name: 'reCAPTCHA',
    category: 'Security',
    website: 'https://www.google.com/recaptcha',
    patterns: {
      html: [/google\.com\/recaptcha/, /g-recaptcha/],
      scripts: [/recaptcha\/api\.js/]
    }
  }
];

export async function techDetect(input: TechDetectInput): Promise<{
  success: boolean;
  url: string;
  technologies: Technology[];
  error?: string;
}> {
  const { url, timeout } = input;

  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), timeout);

    const response = await fetch(url, {
      headers: {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
      },
      signal: controller.signal
    });

    clearTimeout(timeoutId);

    const html = await response.text();
    const headers: Record<string, string> = {};
    response.headers.forEach((value, key) => {
      headers[key.toLowerCase()] = value;
    });

    const technologies: Technology[] = [];

    for (const tech of techPatterns) {
      let matched = false;
      let confidence = 0;
      let version: string | undefined;

      if (tech.patterns.headers) {
        for (const [header, pattern] of Object.entries(tech.patterns.headers)) {
          const value = headers[header];
          if (value && pattern.test(value)) {
            matched = true;
            confidence += 40;

            if (tech.versionPatterns) {
              for (const vp of tech.versionPatterns) {
                const match = value.match(vp);
                if (match) {
                  version = match[1];
                  break;
                }
              }
            }
          }
        }
      }

      if (tech.patterns.html) {
        for (const pattern of tech.patterns.html) {
          if (pattern.test(html)) {
            matched = true;
            confidence += 30;

            if (tech.versionPatterns && !version) {
              for (const vp of tech.versionPatterns) {
                const match = html.match(vp);
                if (match) {
                  version = match[1];
                  break;
                }
              }
            }
          }
        }
      }

      if (tech.patterns.scripts) {
        for (const pattern of tech.patterns.scripts) {
          if (pattern.test(html)) {
            matched = true;
            confidence += 25;
          }
        }
      }

      if (tech.patterns.meta) {
        const metaPattern = /<meta[^>]+name=["']([^"']+)["'][^>]+content=["']([^"']+)["']/gi;
        let metaMatch;
        while ((metaMatch = metaPattern.exec(html)) !== null) {
          const [, name, content] = metaMatch;
          for (const [metaName, pattern] of Object.entries(tech.patterns.meta)) {
            if (name.toLowerCase() === metaName.toLowerCase() && pattern.test(content)) {
              matched = true;
              confidence += 35;

              if (tech.versionPatterns && !version) {
                for (const vp of tech.versionPatterns) {
                  const vm = content.match(vp);
                  if (vm) {
                    version = vm[1];
                    break;
                  }
                }
              }
            }
          }
        }
      }

      if (matched) {
        technologies.push({
          name: tech.name,
          category: tech.category,
          version,
          confidence: Math.min(confidence, 100),
          website: tech.website
        });
      }
    }

    technologies.sort((a, b) => b.confidence - a.confidence);

    return {
      success: true,
      url,
      technologies
    };
  } catch (err) {
    return {
      success: false,
      url,
      technologies: [],
      error: err instanceof Error ? err.message : 'Request failed'
    };
  }
}
