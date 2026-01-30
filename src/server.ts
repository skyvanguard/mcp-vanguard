import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import {
  CallToolRequestSchema,
  ListToolsRequestSchema
} from '@modelcontextprotocol/sdk/types.js';

import { PermissionTier, getToolPermission } from './config.js';
import { auditLogger } from './utils/audit.js';
import { toSafeError, formatSafeError, ToolError } from './utils/safe-error.js';

// Recon tools
import { subdomainEnumSchema, subdomainEnum } from './tools/recon/subdomain.js';
import { portScanSchema, portScan } from './tools/recon/port-scan.js';
import { whoisSchema, whoisLookup } from './tools/recon/whois.js';
import { dnsRecordsSchema, dnsRecords } from './tools/recon/dns.js';

// Web tools
import { ffufSchema, ffufScan } from './tools/web/ffuf.js';
import { nucleiSchema, nucleiScan } from './tools/web/nuclei.js';
import { headersCheckSchema, headersCheck } from './tools/web/headers.js';
import { techDetectSchema, techDetect } from './tools/web/tech-detect.js';
import { waybackSchema, waybackSearch } from './tools/web/wayback.js';
import { sslCheckSchema, sslCheck } from './tools/web/ssl-check.js';
import { corsCheckSchema, corsCheck } from './tools/web/cors-check.js';
import { robotsSitemapSchema, robotsSitemap } from './tools/web/robots-sitemap.js';
import { jsEndpointsSchema, jsEndpoints } from './tools/web/js-endpoints.js';
import { paramMinerSchema, paramMiner } from './tools/web/param-miner.js';

// OSINT tools
import { certSearchSchema, certSearch } from './tools/osint/certs.js';
import { githubDorksSchema, githubDorks } from './tools/osint/github-dorks.js';
import { cveLookupSchema, cveLookup } from './tools/osint/cve-lookup.js';

// Utils
import { setScopeSchema, setScopeTargets, checkScopeSchema, checkScopeTarget } from './tools/utils/scope.js';
import { generateReportSchema, generateReport } from './tools/utils/report.js';
import { exportHtmlSchema, exportHtml } from './tools/utils/export-html.js';
import { auditStatsSchema, auditStats } from './tools/utils/audit-stats.js';

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function zodToJsonSchema(zodSchema: any): Record<string, unknown> {
  const shape = zodSchema._def.shape?.() || zodSchema.shape;

  const properties: Record<string, Record<string, unknown>> = {};
  const required: string[] = [];

  for (const [key, value] of Object.entries(shape)) {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const field = value as any;
    const fieldDef = field._def;

    let type = 'string';
    let description = fieldDef.description || '';
    let items: Record<string, unknown> | undefined;
    let enumValues: string[] | undefined;
    let defaultValue: unknown;

    if (fieldDef.typeName === 'ZodString') {
      type = 'string';
    } else if (fieldDef.typeName === 'ZodNumber') {
      type = 'number';
    } else if (fieldDef.typeName === 'ZodBoolean') {
      type = 'boolean';
    } else if (fieldDef.typeName === 'ZodArray') {
      type = 'array';
      const innerType = fieldDef.type?._def?.typeName;
      if (innerType === 'ZodString') {
        items = { type: 'string' };
      } else if (innerType === 'ZodEnum') {
        items = { type: 'string', enum: fieldDef.type._def.values };
      } else {
        items = { type: 'string' };
      }
    } else if (fieldDef.typeName === 'ZodEnum') {
      type = 'string';
      enumValues = fieldDef.values;
    } else if (fieldDef.typeName === 'ZodDefault') {
      const inner = fieldDef.innerType._def;
      defaultValue = fieldDef.defaultValue();

      if (inner.typeName === 'ZodString') {
        type = 'string';
      } else if (inner.typeName === 'ZodNumber') {
        type = 'number';
      } else if (inner.typeName === 'ZodBoolean') {
        type = 'boolean';
      } else if (inner.typeName === 'ZodArray') {
        type = 'array';
        const arrayInner = inner.type?._def;
        if (arrayInner?.typeName === 'ZodEnum') {
          items = { type: 'string', enum: arrayInner.values };
        } else {
          items = { type: 'string' };
        }
      } else if (inner.typeName === 'ZodEnum') {
        type = 'string';
        enumValues = inner.values;
      }

      description = inner.description || description;
    } else if (fieldDef.typeName === 'ZodOptional') {
      const inner = fieldDef.innerType._def;
      if (inner.typeName === 'ZodString') {
        type = 'string';
      } else if (inner.typeName === 'ZodNumber') {
        type = 'number';
      } else if (inner.typeName === 'ZodRecord') {
        type = 'object';
      } else if (inner.typeName === 'ZodArray') {
        type = 'array';
        items = { type: 'string' };
      } else if (inner.typeName === 'ZodObject') {
        type = 'object';
      }
      description = inner.description || description;
    } else if (fieldDef.typeName === 'ZodRecord') {
      type = 'object';
    } else if (fieldDef.typeName === 'ZodObject') {
      type = 'object';
    }

    const prop: Record<string, unknown> = { type, description };
    if (items) prop.items = items;
    if (enumValues) prop.enum = enumValues;
    if (defaultValue !== undefined) prop.default = defaultValue;

    properties[key] = prop;

    if (!fieldDef.typeName?.includes('Optional') && !fieldDef.typeName?.includes('Default')) {
      required.push(key);
    }
  }

  const schema: Record<string, unknown> = {
    type: 'object',
    properties
  };

  if (required.length > 0) {
    schema.required = required;
  }

  return schema;
}

interface ToolDefinition {
  name: string;
  description: string;
  inputSchema: Record<string, unknown>;
}

const tools: ToolDefinition[] = [
  // === RECON TOOLS ===
  {
    name: 'vanguard_subdomain_enum',
    description: 'Enumerate subdomains using crt.sh and DNS bruteforce. DANGEROUS: Active reconnaissance.',
    inputSchema: zodToJsonSchema(subdomainEnumSchema)
  },
  {
    name: 'vanguard_port_scan',
    description: 'Scan ports on a target. Uses nmap or TCP connect. DANGEROUS: Active scanning.',
    inputSchema: zodToJsonSchema(portScanSchema)
  },
  {
    name: 'vanguard_whois',
    description: 'WHOIS lookup for domain or IP. SAFE: Passive reconnaissance.',
    inputSchema: zodToJsonSchema(whoisSchema)
  },
  {
    name: 'vanguard_dns_records',
    description: 'Query DNS records (A, AAAA, MX, NS, TXT, etc). SAFE: Passive.',
    inputSchema: zodToJsonSchema(dnsRecordsSchema)
  },

  // === WEB TOOLS ===
  {
    name: 'vanguard_ffuf',
    description: 'Web fuzzing with ffuf. Use FUZZ keyword in URL. DANGEROUS: Active.',
    inputSchema: zodToJsonSchema(ffufSchema)
  },
  {
    name: 'vanguard_nuclei_scan',
    description: 'Vulnerability scanning with nuclei templates. DANGEROUS: Active.',
    inputSchema: zodToJsonSchema(nucleiSchema)
  },
  {
    name: 'vanguard_headers_check',
    description: 'Analyze security headers (HSTS, CSP, X-Frame-Options). SAFE: Passive.',
    inputSchema: zodToJsonSchema(headersCheckSchema)
  },
  {
    name: 'vanguard_tech_detect',
    description: 'Detect website technologies (CMS, frameworks, CDN). SAFE: Passive.',
    inputSchema: zodToJsonSchema(techDetectSchema)
  },
  {
    name: 'vanguard_wayback',
    description: 'Search Wayback Machine for historical URLs. SAFE: Passive OSINT.',
    inputSchema: zodToJsonSchema(waybackSchema)
  },
  {
    name: 'vanguard_ssl_check',
    description: 'Analyze SSL/TLS certificate and configuration. SAFE: Passive.',
    inputSchema: zodToJsonSchema(sslCheckSchema)
  },
  {
    name: 'vanguard_cors_check',
    description: 'Test for CORS misconfigurations. SAFE: Passive analysis.',
    inputSchema: zodToJsonSchema(corsCheckSchema)
  },
  {
    name: 'vanguard_robots_sitemap',
    description: 'Parse robots.txt and sitemap.xml for interesting paths. SAFE: Passive.',
    inputSchema: zodToJsonSchema(robotsSitemapSchema)
  },
  {
    name: 'vanguard_js_endpoints',
    description: 'Extract endpoints, secrets, and domains from JavaScript. SAFE: Passive.',
    inputSchema: zodToJsonSchema(jsEndpointsSchema)
  },
  {
    name: 'vanguard_param_miner',
    description: 'Discover hidden parameters. DANGEROUS: Active probing.',
    inputSchema: zodToJsonSchema(paramMinerSchema)
  },

  // === OSINT TOOLS ===
  {
    name: 'vanguard_cert_search',
    description: 'Search certificate transparency logs (crt.sh). SAFE: Passive OSINT.',
    inputSchema: zodToJsonSchema(certSearchSchema)
  },
  {
    name: 'vanguard_github_dorks',
    description: 'Generate GitHub dork queries for sensitive data. DANGEROUS: May reveal secrets.',
    inputSchema: zodToJsonSchema(githubDorksSchema)
  },
  {
    name: 'vanguard_cve_lookup',
    description: 'Search CVE database (NVD) by product or CVE ID. SAFE: Passive.',
    inputSchema: zodToJsonSchema(cveLookupSchema)
  },

  // === UTILITY TOOLS ===
  {
    name: 'vanguard_set_scope',
    description: 'Define authorized targets (domains, IPs, CIDR). SAFE.',
    inputSchema: zodToJsonSchema(setScopeSchema)
  },
  {
    name: 'vanguard_check_scope',
    description: 'Verify if target is within defined scope. SAFE.',
    inputSchema: zodToJsonSchema(checkScopeSchema)
  },
  {
    name: 'vanguard_generate_report',
    description: 'Generate markdown security report from findings. SAFE.',
    inputSchema: zodToJsonSchema(generateReportSchema)
  },
  {
    name: 'vanguard_export_html',
    description: 'Convert markdown report to styled HTML. SAFE.',
    inputSchema: zodToJsonSchema(exportHtmlSchema)
  },
  {
    name: 'vanguard_audit_stats',
    description: 'View audit log statistics and security events. SAFE: Internal monitoring.',
    inputSchema: zodToJsonSchema(auditStatsSchema)
  }
];

export async function createServer(): Promise<Server> {
  const server = new Server(
    {
      name: 'mcp-vanguard',
      version: '1.1.0'
    },
    {
      capabilities: {
        tools: {}
      }
    }
  );

  server.setRequestHandler(ListToolsRequestSchema, async () => {
    return { tools };
  });

  server.setRequestHandler(CallToolRequestSchema, async (request) => {
    const { name, arguments: args } = request.params;
    const startTime = Date.now();

    const permission = getToolPermission(name);
    if (permission === PermissionTier.BLOCKED) {
      auditLogger.logSecurityEvent(name, 'tool_blocked', { permission: 'BLOCKED' });
      return {
        content: [{
          type: 'text',
          text: formatSafeError(new ToolError('TOOL_BLOCKED', name).toSafeError())
        }],
        isError: true
      };
    }

    try {
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      let result: any;

      switch (name) {
        // Recon
        case 'vanguard_subdomain_enum':
          result = await subdomainEnum(subdomainEnumSchema.parse(args));
          break;
        case 'vanguard_port_scan':
          result = await portScan(portScanSchema.parse(args));
          break;
        case 'vanguard_whois':
          result = await whoisLookup(whoisSchema.parse(args));
          break;
        case 'vanguard_dns_records':
          result = await dnsRecords(dnsRecordsSchema.parse(args));
          break;

        // Web
        case 'vanguard_ffuf':
          result = await ffufScan(ffufSchema.parse(args));
          break;
        case 'vanguard_nuclei_scan':
          result = await nucleiScan(nucleiSchema.parse(args));
          break;
        case 'vanguard_headers_check':
          result = await headersCheck(headersCheckSchema.parse(args));
          break;
        case 'vanguard_tech_detect':
          result = await techDetect(techDetectSchema.parse(args));
          break;
        case 'vanguard_wayback':
          result = await waybackSearch(waybackSchema.parse(args));
          break;
        case 'vanguard_ssl_check':
          result = await sslCheck(sslCheckSchema.parse(args));
          break;
        case 'vanguard_cors_check':
          result = await corsCheck(corsCheckSchema.parse(args));
          break;
        case 'vanguard_robots_sitemap':
          result = await robotsSitemap(robotsSitemapSchema.parse(args));
          break;
        case 'vanguard_js_endpoints':
          result = await jsEndpoints(jsEndpointsSchema.parse(args));
          break;
        case 'vanguard_param_miner':
          result = await paramMiner(paramMinerSchema.parse(args));
          break;

        // OSINT
        case 'vanguard_cert_search':
          result = await certSearch(certSearchSchema.parse(args));
          break;
        case 'vanguard_github_dorks':
          result = await githubDorks(githubDorksSchema.parse(args));
          break;
        case 'vanguard_cve_lookup':
          result = await cveLookup(cveLookupSchema.parse(args));
          break;

        // Utils
        case 'vanguard_set_scope':
          result = setScopeTargets(setScopeSchema.parse(args));
          break;
        case 'vanguard_check_scope':
          result = checkScopeTarget(checkScopeSchema.parse(args));
          break;
        case 'vanguard_generate_report':
          result = generateReport(generateReportSchema.parse(args));
          break;
        case 'vanguard_export_html':
          result = exportHtml(exportHtmlSchema.parse(args));
          break;
        case 'vanguard_audit_stats':
          result = auditStats(auditStatsSchema.parse(args));
          break;

        default:
          auditLogger.logToolCall(name, undefined, 'failure', undefined, 'Unknown tool');
          return {
            content: [{
              type: 'text',
              text: formatSafeError(new ToolError('INVALID_INPUT', name, 'Unknown tool').toSafeError())
            }],
            isError: true
          };
      }

      // Log successful tool execution
      const duration = Date.now() - startTime;
      auditLogger.logToolCall(name, undefined, 'success', undefined, undefined, duration);

      return {
        content: [{
          type: 'text',
          text: JSON.stringify(result, null, 2)
        }]
      };
    } catch (error) {
      const duration = Date.now() - startTime;
      const safeError = toSafeError(error, name);

      auditLogger.logToolCall(
        name,
        undefined,
        'failure',
        undefined,
        safeError.message,
        duration
      );

      return {
        content: [{
          type: 'text',
          text: formatSafeError(safeError)
        }],
        isError: true
      };
    }
  });

  return server;
}

export async function runServer(): Promise<void> {
  const server = await createServer();
  const transport = new StdioServerTransport();
  await server.connect(transport);
}
