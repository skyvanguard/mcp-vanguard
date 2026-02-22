import { z } from 'zod';

export const googleDorksSchema = z.object({
  domain: z.string().describe('Target domain for dork queries'),
  categories: z.array(z.enum([
    'sensitive_files', 'login_pages', 'exposed_data', 'directories',
    'config_files', 'database', 'api_endpoints', 'cloud_storage',
    'error_messages', 'subdomains'
  ])).default(['sensitive_files', 'login_pages', 'exposed_data', 'directories'])
    .describe('Categories of dorks to generate')
});

export type GoogleDorksInput = z.infer<typeof googleDorksSchema>;

interface DorkEntry {
  category: string;
  dork: string;
  description: string;
  risk: 'low' | 'medium' | 'high';
}

const DORK_TEMPLATES: Record<string, Array<{ template: string; description: string; risk: 'low' | 'medium' | 'high' }>> = {
  sensitive_files: [
    { template: 'site:{domain} filetype:pdf', description: 'PDF documents', risk: 'low' },
    { template: 'site:{domain} filetype:xlsx OR filetype:xls OR filetype:csv', description: 'Spreadsheets', risk: 'medium' },
    { template: 'site:{domain} filetype:doc OR filetype:docx', description: 'Word documents', risk: 'low' },
    { template: 'site:{domain} filetype:sql OR filetype:db OR filetype:sqlite', description: 'Database files', risk: 'high' },
    { template: 'site:{domain} filetype:log', description: 'Log files', risk: 'high' },
    { template: 'site:{domain} filetype:bak OR filetype:backup OR filetype:old', description: 'Backup files', risk: 'high' },
    { template: 'site:{domain} filetype:env OR filetype:cfg OR filetype:conf', description: 'Config files', risk: 'high' }
  ],
  login_pages: [
    { template: 'site:{domain} inurl:login OR inurl:signin OR inurl:auth', description: 'Login pages', risk: 'low' },
    { template: 'site:{domain} inurl:admin OR inurl:dashboard OR inurl:panel', description: 'Admin panels', risk: 'medium' },
    { template: 'site:{domain} intitle:"login" OR intitle:"sign in"', description: 'Login page titles', risk: 'low' },
    { template: 'site:{domain} inurl:wp-admin OR inurl:wp-login', description: 'WordPress admin', risk: 'medium' }
  ],
  exposed_data: [
    { template: 'site:{domain} "password" OR "passwd" OR "credentials" filetype:txt', description: 'Password files', risk: 'high' },
    { template: 'site:{domain} "api_key" OR "apikey" OR "api-key" OR "secret_key"', description: 'API keys in pages', risk: 'high' },
    { template: 'site:{domain} "BEGIN RSA PRIVATE KEY" OR "BEGIN PRIVATE KEY"', description: 'Private keys', risk: 'high' },
    { template: 'site:{domain} inurl:token OR inurl:secret OR inurl:key', description: 'Tokens in URLs', risk: 'high' }
  ],
  directories: [
    { template: 'site:{domain} intitle:"index of /"', description: 'Directory listings', risk: 'medium' },
    { template: 'site:{domain} intitle:"index of" "parent directory"', description: 'Open directories', risk: 'medium' },
    { template: 'site:{domain} inurl:/backup/ OR inurl:/bak/ OR inurl:/old/', description: 'Backup directories', risk: 'high' }
  ],
  config_files: [
    { template: 'site:{domain} filetype:xml "configuration"', description: 'XML configs', risk: 'medium' },
    { template: 'site:{domain} filetype:json "password" OR "secret"', description: 'JSON with secrets', risk: 'high' },
    { template: 'site:{domain} filetype:yml OR filetype:yaml', description: 'YAML configs', risk: 'medium' },
    { template: 'site:{domain} inurl:web.config OR inurl:.htaccess', description: 'Web server configs', risk: 'high' }
  ],
  database: [
    { template: 'site:{domain} filetype:sql "CREATE TABLE" OR "INSERT INTO"', description: 'SQL dumps', risk: 'high' },
    { template: 'site:{domain} inurl:phpmyadmin OR inurl:adminer', description: 'DB admin tools', risk: 'high' },
    { template: 'site:{domain} "MySQL" "error" OR "syntax error"', description: 'SQL errors', risk: 'medium' }
  ],
  api_endpoints: [
    { template: 'site:{domain} inurl:api OR inurl:/v1/ OR inurl:/v2/', description: 'API endpoints', risk: 'low' },
    { template: 'site:{domain} inurl:swagger OR inurl:openapi OR inurl:graphql', description: 'API documentation', risk: 'medium' },
    { template: 'site:{domain} filetype:json inurl:api', description: 'API JSON responses', risk: 'low' }
  ],
  cloud_storage: [
    { template: 'site:s3.amazonaws.com "{domain}"', description: 'S3 buckets', risk: 'medium' },
    { template: 'site:blob.core.windows.net "{domain}"', description: 'Azure blobs', risk: 'medium' },
    { template: 'site:storage.googleapis.com "{domain}"', description: 'GCS buckets', risk: 'medium' }
  ],
  error_messages: [
    { template: 'site:{domain} "stack trace" OR "traceback" OR "error occurred"', description: 'Stack traces', risk: 'medium' },
    { template: 'site:{domain} "Warning:" "on line"', description: 'PHP warnings', risk: 'medium' },
    { template: 'site:{domain} "Fatal error" OR "500 Internal Server Error"', description: 'Server errors', risk: 'medium' }
  ],
  subdomains: [
    { template: 'site:*.{domain} -www', description: 'Subdomains via Google', risk: 'low' },
    { template: 'site:{domain} -www -inurl:www', description: 'Non-www pages', risk: 'low' }
  ]
};

export async function googleDorks(input: GoogleDorksInput): Promise<{
  success: boolean;
  domain: string;
  dorks: DorkEntry[];
  totalDorks: number;
}> {
  const { domain, categories } = input;
  const dorks: DorkEntry[] = [];

  for (const category of categories) {
    const templates = DORK_TEMPLATES[category] || [];
    for (const t of templates) {
      dorks.push({
        category,
        dork: t.template.replace(/{domain}/g, domain),
        description: t.description,
        risk: t.risk
      });
    }
  }

  return {
    success: true,
    domain,
    dorks,
    totalDorks: dorks.length
  };
}
