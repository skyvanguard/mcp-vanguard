import { z } from 'zod';

export const githubDorksSchema = z.object({
  target: z.string().describe('Organization name, username, or domain to search'),
  searchType: z.enum(['org', 'user', 'domain', 'custom']).default('domain'),
  customQuery: z.string().optional().describe('Custom search query (for searchType=custom)'),
  dorkCategories: z.array(z.enum([
    'secrets', 'configs', 'credentials', 'api_keys', 'tokens',
    'database', 'aws', 'azure', 'gcp', 'internal'
  ])).default(['secrets', 'credentials', 'api_keys']).describe('Categories of dorks to run'),
  maxResults: z.number().default(100).describe('Maximum results per query')
});

export type GithubDorksInput = z.infer<typeof githubDorksSchema>;

interface DorkResult {
  category: string;
  dorkName: string;
  query: string;
  matchCount: number;
  sampleMatches: Array<{
    repository: string;
    path: string;
    url: string;
  }>;
}

const dorkTemplates: Record<string, Array<{ name: string; query: string }>> = {
  secrets: [
    { name: 'Private Keys', query: '-----BEGIN RSA PRIVATE KEY-----' },
    { name: 'Private Keys EC', query: '-----BEGIN EC PRIVATE KEY-----' },
    { name: 'PGP Private', query: '-----BEGIN PGP PRIVATE KEY BLOCK-----' },
    { name: 'SSH Private', query: '-----BEGIN OPENSSH PRIVATE KEY-----' }
  ],
  credentials: [
    { name: 'Password in URL', query: 'password://' },
    { name: 'Password Assignment', query: 'password =' },
    { name: 'DB Password', query: 'db_password' },
    { name: 'Secret Key', query: 'secret_key =' },
    { name: 'Auth Token', query: 'auth_token =' }
  ],
  api_keys: [
    { name: 'API Key Generic', query: 'api_key =' },
    { name: 'API Secret', query: 'api_secret =' },
    { name: 'Stripe Key', query: 'sk_live_' },
    { name: 'Stripe Test', query: 'sk_test_' },
    { name: 'Slack Token', query: 'xox[baprs]-' },
    { name: 'GitHub Token', query: 'ghp_' },
    { name: 'SendGrid', query: 'SG.' }
  ],
  tokens: [
    { name: 'JWT Token', query: 'eyJ' },
    { name: 'Bearer Token', query: 'bearer ' },
    { name: 'Access Token', query: 'access_token =' },
    { name: 'Refresh Token', query: 'refresh_token =' }
  ],
  configs: [
    { name: 'Environment File', query: 'filename:.env' },
    { name: 'Docker Compose Secrets', query: 'filename:docker-compose.yml password' },
    { name: 'Config JSON', query: 'filename:config.json password' },
    { name: 'Settings Prod', query: 'filename:settings.py SECRET' },
    { name: 'Application Props', query: 'filename:application.properties password' }
  ],
  database: [
    { name: 'MySQL Connection', query: 'mysql://' },
    { name: 'PostgreSQL Connection', query: 'postgresql://' },
    { name: 'MongoDB Connection', query: 'mongodb://' },
    { name: 'Redis Connection', query: 'redis://' },
    { name: 'Database URL', query: 'DATABASE_URL=' }
  ],
  aws: [
    { name: 'AWS Access Key', query: 'AKIA' },
    { name: 'AWS Secret', query: 'aws_secret_access_key' },
    { name: 'S3 Bucket', query: 's3.amazonaws.com' },
    { name: 'AWS Config', query: 'filename:.aws/credentials' }
  ],
  azure: [
    { name: 'Azure Storage', query: 'AccountKey=' },
    { name: 'Azure Connection', query: 'blob.core.windows.net' },
    { name: 'Azure Secret', query: 'AZURE_' }
  ],
  gcp: [
    { name: 'GCP Service Account', query: 'filename:service_account.json' },
    { name: 'GCP Private Key', query: '"private_key_id"' },
    { name: 'Firebase Config', query: 'firebaseConfig' }
  ],
  internal: [
    { name: 'Internal URL', query: 'internal.' },
    { name: 'Staging URL', query: 'staging.' },
    { name: 'Dev URL', query: 'dev.' },
    { name: 'VPN Config', query: 'filename:.ovpn' },
    { name: 'TODO Security', query: 'TODO security' }
  ]
};

export async function githubDorks(input: GithubDorksInput): Promise<{
  success: boolean;
  target: string;
  results: DorkResult[];
  summary: {
    totalMatches: number;
    categoriesSearched: number;
    dorksExecuted: number;
    highRiskFindings: number;
  };
  searchUrls: string[];
  error?: string;
}> {
  const { target, searchType, customQuery, dorkCategories, maxResults } = input;

  const results: DorkResult[] = [];
  const searchUrls: string[] = [];
  let totalMatches = 0;
  let highRiskFindings = 0;

  let baseQuery: string;
  switch (searchType) {
    case 'org':
      baseQuery = `org:${target}`;
      break;
    case 'user':
      baseQuery = `user:${target}`;
      break;
    case 'domain':
      baseQuery = `"${target}"`;
      break;
    case 'custom':
      baseQuery = customQuery || target;
      break;
  }

  const highRiskDorks = [
    'Private Keys', 'AWS Access Key', 'Stripe Key', 'Password in URL',
    'GCP Service Account', 'Azure Storage', 'SSH Private'
  ];

  let dorksExecuted = 0;

  for (const category of dorkCategories) {
    const dorks = dorkTemplates[category] || [];

    for (const dork of dorks) {
      const fullQuery = `${baseQuery} ${dork.query}`;
      const encodedQuery = encodeURIComponent(fullQuery);
      const searchUrl = `https://github.com/search?q=${encodedQuery}&type=code`;

      searchUrls.push(searchUrl);
      dorksExecuted++;

      results.push({
        category,
        dorkName: dork.name,
        query: fullQuery,
        matchCount: 0,
        sampleMatches: []
      });

      if (highRiskDorks.includes(dork.name)) {
        highRiskFindings++;
      }
    }
  }

  return {
    success: true,
    target,
    results,
    summary: {
      totalMatches,
      categoriesSearched: dorkCategories.length,
      dorksExecuted,
      highRiskFindings
    },
    searchUrls
  };
}

export function generateDorkReport(
  target: string,
  results: DorkResult[]
): string {
  const lines: string[] = [
    `# GitHub Dork Report: ${target}`,
    '',
    `Generated: ${new Date().toISOString()}`,
    '',
    '## Summary',
    '',
    `- Total dorks executed: ${results.length}`,
    `- Categories searched: ${new Set(results.map(r => r.category)).size}`,
    '',
    '## Search URLs',
    '',
    'Click these links to manually review results on GitHub:',
    ''
  ];

  const byCategory = new Map<string, DorkResult[]>();
  for (const result of results) {
    const existing = byCategory.get(result.category) || [];
    existing.push(result);
    byCategory.set(result.category, existing);
  }

  for (const [category, categoryResults] of byCategory) {
    lines.push(`### ${category.toUpperCase()}`);
    lines.push('');

    for (const result of categoryResults) {
      const encodedQuery = encodeURIComponent(result.query);
      const url = `https://github.com/search?q=${encodedQuery}&type=code`;
      lines.push(`- [${result.dorkName}](${url})`);
    }

    lines.push('');
  }

  lines.push('## Notes');
  lines.push('');
  lines.push('- GitHub API rate limits prevent automated searching');
  lines.push('- Manual review of each URL is recommended');
  lines.push('- False positives are common; verify each finding');
  lines.push('- Consider using GitHub Advanced Search for refinement');

  return lines.join('\n');
}
