import { z } from 'zod';

export enum PermissionTier {
  SAFE = 'SAFE',
  DANGEROUS = 'DANGEROUS',
  BLOCKED = 'BLOCKED'
}

export const ConfigSchema = z.object({
  wslEnabled: z.boolean().default(true),
  wslDistro: z.string().default('kali-linux'),
  rateLimitMs: z.number().default(1000),
  maxConcurrent: z.number().default(3),
  timeout: z.number().default(300000),
  scope: z.array(z.string()).default([]),
  outputDir: z.string().optional()
});

export type Config = z.infer<typeof ConfigSchema>;

export const defaultConfig: Config = {
  wslEnabled: true,
  wslDistro: 'kali-linux',
  rateLimitMs: 1000,
  maxConcurrent: 3,
  timeout: 300000,
  scope: [],
  outputDir: undefined
};

let currentConfig: Config = { ...defaultConfig };

export function getConfig(): Config {
  return currentConfig;
}

export function updateConfig(updates: Partial<Config>): Config {
  currentConfig = { ...currentConfig, ...updates };
  return currentConfig;
}

export function setScope(targets: string[]): void {
  currentConfig.scope = targets;
}

export function getScope(): string[] {
  return currentConfig.scope;
}

export function isInScope(target: string): boolean {
  if (currentConfig.scope.length === 0) {
    return true;
  }

  const normalizedTarget = target.toLowerCase();

  return currentConfig.scope.some(scopeItem => {
    const normalizedScope = scopeItem.toLowerCase();

    if (normalizedScope.startsWith('*.')) {
      const domain = normalizedScope.slice(2);
      return normalizedTarget === domain ||
             normalizedTarget.endsWith('.' + domain);
    }

    if (normalizedScope.includes('/')) {
      return normalizedTarget.startsWith(normalizedScope) ||
             normalizedTarget.includes(normalizedScope);
    }

    return normalizedTarget === normalizedScope ||
           normalizedTarget.endsWith('.' + normalizedScope);
  });
}

export const toolPermissions: Record<string, PermissionTier> = {
  // SAFE - Passive reconnaissance
  'vanguard_dns_records': PermissionTier.SAFE,
  'vanguard_whois': PermissionTier.SAFE,
  'vanguard_headers_check': PermissionTier.SAFE,
  'vanguard_cert_search': PermissionTier.SAFE,
  'vanguard_wayback': PermissionTier.SAFE,
  'vanguard_tech_detect': PermissionTier.SAFE,
  'vanguard_ssl_check': PermissionTier.SAFE,
  'vanguard_cors_check': PermissionTier.SAFE,
  'vanguard_robots_sitemap': PermissionTier.SAFE,
  'vanguard_js_endpoints': PermissionTier.SAFE,
  'vanguard_cve_lookup': PermissionTier.SAFE,
  'vanguard_set_scope': PermissionTier.SAFE,
  'vanguard_check_scope': PermissionTier.SAFE,
  'vanguard_generate_report': PermissionTier.SAFE,
  'vanguard_export_html': PermissionTier.SAFE,
  'vanguard_audit_stats': PermissionTier.SAFE,

  // DANGEROUS - Active scanning/probing
  'vanguard_subdomain_enum': PermissionTier.DANGEROUS,
  'vanguard_port_scan': PermissionTier.DANGEROUS,
  'vanguard_ffuf': PermissionTier.DANGEROUS,
  'vanguard_nuclei_scan': PermissionTier.DANGEROUS,
  'vanguard_github_dorks': PermissionTier.DANGEROUS,
  'vanguard_param_miner': PermissionTier.DANGEROUS
};

export function getToolPermission(toolName: string): PermissionTier {
  return toolPermissions[toolName] ?? PermissionTier.BLOCKED;
}
