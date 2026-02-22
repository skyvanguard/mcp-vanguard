import { PermissionTier } from '../../config.js';
import { ToolDefinition } from '../../types/tool.js';
import { ffufSchema, ffufScan } from './ffuf.js';
import { nucleiSchema, nucleiScan } from './nuclei.js';
import { headersCheckSchema, headersCheck } from './headers.js';
import { techDetectSchema, techDetect } from './tech-detect.js';
import { waybackSchema, waybackSearch } from './wayback.js';
import { sslCheckSchema, sslCheck } from './ssl-check.js';
import { corsCheckSchema, corsCheck } from './cors-check.js';
import { robotsSitemapSchema, robotsSitemap } from './robots-sitemap.js';
import { jsEndpointsSchema, jsEndpoints } from './js-endpoints.js';
import { paramMinerSchema, paramMiner } from './param-miner.js';

export const webTools: ToolDefinition[] = [
  {
    name: 'vanguard_ffuf',
    description: 'Web fuzzing with ffuf. Use FUZZ keyword in URL. DANGEROUS: Active.',
    category: 'web',
    permission: PermissionTier.DANGEROUS,
    schema: ffufSchema,
    handler: ffufScan,
    executionMode: 'hybrid',
    wslCommands: ['ffuf'],
    windowsCommands: ['ffuf'],
    requiresScope: true,
    tags: ['fuzzing', 'directory', 'bruteforce']
  },
  {
    name: 'vanguard_nuclei_scan',
    description: 'Vulnerability scanning with nuclei templates. DANGEROUS: Active.',
    category: 'web',
    permission: PermissionTier.DANGEROUS,
    schema: nucleiSchema,
    handler: nucleiScan,
    executionMode: 'hybrid',
    wslCommands: ['nuclei'],
    windowsCommands: ['nuclei'],
    requiresScope: true,
    tags: ['vulnerability', 'scanner', 'nuclei']
  },
  {
    name: 'vanguard_headers_check',
    description: 'Analyze security headers (HSTS, CSP, X-Frame-Options). SAFE: Passive.',
    category: 'web',
    permission: PermissionTier.SAFE,
    schema: headersCheckSchema,
    handler: headersCheck,
    executionMode: 'native',
    tags: ['headers', 'security', 'http']
  },
  {
    name: 'vanguard_tech_detect',
    description: 'Detect website technologies (CMS, frameworks, CDN). SAFE: Passive.',
    category: 'web',
    permission: PermissionTier.SAFE,
    schema: techDetectSchema,
    handler: techDetect,
    executionMode: 'native',
    tags: ['technology', 'detection', 'fingerprint']
  },
  {
    name: 'vanguard_wayback',
    description: 'Search Wayback Machine for historical URLs. SAFE: Passive OSINT.',
    category: 'web',
    permission: PermissionTier.SAFE,
    schema: waybackSchema,
    handler: waybackSearch,
    executionMode: 'api',
    tags: ['wayback', 'archive', 'history']
  },
  {
    name: 'vanguard_ssl_check',
    description: 'Analyze SSL/TLS certificate and configuration. SAFE: Passive.',
    category: 'web',
    permission: PermissionTier.SAFE,
    schema: sslCheckSchema,
    handler: sslCheck,
    executionMode: 'native',
    tags: ['ssl', 'tls', 'certificate']
  },
  {
    name: 'vanguard_cors_check',
    description: 'Test for CORS misconfigurations. SAFE: Passive analysis.',
    category: 'web',
    permission: PermissionTier.SAFE,
    schema: corsCheckSchema,
    handler: corsCheck,
    executionMode: 'native',
    tags: ['cors', 'misconfiguration']
  },
  {
    name: 'vanguard_robots_sitemap',
    description: 'Parse robots.txt and sitemap.xml for interesting paths. SAFE: Passive.',
    category: 'web',
    permission: PermissionTier.SAFE,
    schema: robotsSitemapSchema,
    handler: robotsSitemap,
    executionMode: 'native',
    tags: ['robots', 'sitemap', 'discovery']
  },
  {
    name: 'vanguard_js_endpoints',
    description: 'Extract endpoints, secrets, and domains from JavaScript. SAFE: Passive.',
    category: 'web',
    permission: PermissionTier.SAFE,
    schema: jsEndpointsSchema,
    handler: jsEndpoints,
    executionMode: 'native',
    tags: ['javascript', 'endpoints', 'secrets']
  },
  {
    name: 'vanguard_param_miner',
    description: 'Discover hidden parameters. DANGEROUS: Active probing.',
    category: 'web',
    permission: PermissionTier.DANGEROUS,
    schema: paramMinerSchema,
    handler: paramMiner,
    executionMode: 'native',
    requiresScope: true,
    tags: ['parameters', 'discovery', 'hidden']
  }
];
