import { z } from 'zod';

export enum PermissionTier {
  SAFE = 'SAFE',
  DANGEROUS = 'DANGEROUS',
  BLOCKED = 'BLOCKED'
}

export const ApiKeysSchema = z.object({
  shodan: z.string().optional(),
  virustotal: z.string().optional(),
  securitytrails: z.string().optional(),
  abuseipdb: z.string().optional(),
  haveibeenpwned: z.string().optional(),
  hunter: z.string().optional()
}).default({});

export const ConfigSchema = z.object({
  wslEnabled: z.boolean().default(true),
  wslDistro: z.string().default('kali-linux'),
  rateLimitMs: z.number().default(1000),
  maxConcurrent: z.number().default(3),
  timeout: z.number().default(300000),
  scope: z.array(z.string()).default([]),
  outputDir: z.string().optional(),
  apiKeys: ApiKeysSchema
});

export type Config = z.infer<typeof ConfigSchema>;

export const defaultConfig: Config = {
  wslEnabled: true,
  wslDistro: 'kali-linux',
  rateLimitMs: 1000,
  maxConcurrent: 3,
  timeout: 300000,
  scope: [],
  outputDir: undefined,
  apiKeys: {}
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

/**
 * Get tool permission. Delegates to registry when available,
 * falls back to BLOCKED for unknown tools.
 *
 * Note: After v2.0.0 refactor, permissions are defined per-tool
 * in their ToolDefinition. This function is kept for backward
 * compatibility and is used by server.ts via registry.getPermission().
 */
export function getToolPermission(toolName: string): PermissionTier {
  // Lazy import to avoid circular dependency
  // In v2.0.0+, server.ts uses registry.getPermission() directly
  return PermissionTier.BLOCKED;
}
