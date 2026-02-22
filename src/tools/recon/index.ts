import { PermissionTier } from '../../config.js';
import { ToolDefinition } from '../../types/tool.js';
import { subdomainEnumSchema, subdomainEnum } from './subdomain.js';
import { portScanSchema, portScan } from './port-scan.js';
import { whoisSchema, whoisLookup } from './whois.js';
import { dnsRecordsSchema, dnsRecords } from './dns.js';

export const reconTools: ToolDefinition[] = [
  {
    name: 'vanguard_subdomain_enum',
    description: 'Enumerate subdomains using crt.sh and DNS bruteforce. DANGEROUS: Active reconnaissance.',
    category: 'recon',
    permission: PermissionTier.DANGEROUS,
    schema: subdomainEnumSchema,
    handler: subdomainEnum,
    executionMode: 'api',
    requiresScope: true,
    tags: ['subdomain', 'enumeration', 'crt.sh']
  },
  {
    name: 'vanguard_port_scan',
    description: 'Scan ports on a target. Uses nmap or TCP connect. DANGEROUS: Active scanning.',
    category: 'recon',
    permission: PermissionTier.DANGEROUS,
    schema: portScanSchema,
    handler: portScan,
    executionMode: 'hybrid',
    wslCommands: ['nmap'],
    windowsCommands: ['nmap'],
    requiresScope: true,
    tags: ['port', 'scan', 'nmap']
  },
  {
    name: 'vanguard_whois',
    description: 'WHOIS lookup for domain or IP. SAFE: Passive reconnaissance.',
    category: 'recon',
    permission: PermissionTier.SAFE,
    schema: whoisSchema,
    handler: whoisLookup,
    executionMode: 'api',
    tags: ['whois', 'domain', 'ip']
  },
  {
    name: 'vanguard_dns_records',
    description: 'Query DNS records (A, AAAA, MX, NS, TXT, etc). SAFE: Passive.',
    category: 'recon',
    permission: PermissionTier.SAFE,
    schema: dnsRecordsSchema,
    handler: dnsRecords,
    executionMode: 'api',
    tags: ['dns', 'records']
  }
];
