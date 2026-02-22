import { PermissionTier } from '../../config.js';
import { ToolDefinition } from '../../types/tool.js';
import { certSearchSchema, certSearch } from './certs.js';
import { githubDorksSchema, githubDorks } from './github-dorks.js';
import { cveLookupSchema, cveLookup } from './cve-lookup.js';
import { emailHunterSchema, emailHunter } from './email-hunter.js';
import { socialMediaSchema, socialMedia } from './social-media.js';
import { domainReputationSchema, domainReputation } from './domain-reputation.js';
import { ipGeolocationSchema, ipGeolocation } from './ip-geolocation.js';
import { asnLookupSchema, asnLookup } from './asn-lookup.js';
import { googleDorksSchema, googleDorks } from './google-dorks.js';
import { shodanSearchSchema, shodanSearch } from './shodan-search.js';
import { breachCheckSchema, breachCheck } from './breach-check.js';
import { metadataExtractSchema, metadataExtract } from './metadata-extract.js';
import { dnsHistorySchema, dnsHistory } from './dns-history.js';
import { faviconHashSchema, faviconHash } from './favicon-hash.js';
import { webArchiveDiffSchema, webArchiveDiff } from './web-archive-diff.js';

export const osintTools: ToolDefinition[] = [
  {
    name: 'vanguard_cert_search',
    description: 'Search certificate transparency logs (crt.sh). SAFE: Passive OSINT.',
    category: 'osint',
    permission: PermissionTier.SAFE,
    schema: certSearchSchema,
    handler: certSearch,
    executionMode: 'api',
    tags: ['certificate', 'transparency', 'crt.sh']
  },
  {
    name: 'vanguard_github_dorks',
    description: 'Generate GitHub dork queries for sensitive data. DANGEROUS: May reveal secrets.',
    category: 'osint',
    permission: PermissionTier.DANGEROUS,
    schema: githubDorksSchema,
    handler: githubDorks,
    executionMode: 'native',
    tags: ['github', 'dorks', 'secrets']
  },
  {
    name: 'vanguard_cve_lookup',
    description: 'Search CVE database (NVD) by product or CVE ID. SAFE: Passive.',
    category: 'osint',
    permission: PermissionTier.SAFE,
    schema: cveLookupSchema,
    handler: cveLookup,
    executionMode: 'api',
    tags: ['cve', 'vulnerability', 'nvd']
  },
  {
    name: 'vanguard_email_hunter',
    description: 'Find email addresses associated with a domain. SAFE: Passive OSINT.',
    category: 'osint',
    permission: PermissionTier.SAFE,
    schema: emailHunterSchema,
    handler: emailHunter,
    executionMode: 'api',
    tags: ['email', 'hunter', 'osint']
  },
  {
    name: 'vanguard_social_media',
    description: 'Check username existence across social media platforms. SAFE: Passive lookups.',
    category: 'osint',
    permission: PermissionTier.SAFE,
    schema: socialMediaSchema,
    handler: socialMedia,
    executionMode: 'api',
    tags: ['social', 'media', 'username', 'osint']
  },
  {
    name: 'vanguard_domain_reputation',
    description: 'Check domain/IP reputation across threat intelligence sources. SAFE: Passive.',
    category: 'osint',
    permission: PermissionTier.SAFE,
    schema: domainReputationSchema,
    handler: domainReputation,
    executionMode: 'api',
    tags: ['reputation', 'threat', 'intelligence', 'virustotal']
  },
  {
    name: 'vanguard_ip_geolocation',
    description: 'Geolocate an IP address (country, city, ISP, ASN). SAFE: Passive.',
    category: 'osint',
    permission: PermissionTier.SAFE,
    schema: ipGeolocationSchema,
    handler: ipGeolocation,
    executionMode: 'api',
    tags: ['geolocation', 'ip', 'location']
  },
  {
    name: 'vanguard_asn_lookup',
    description: 'Lookup ASN info by number, IP, or organization name. SAFE: Passive.',
    category: 'osint',
    permission: PermissionTier.SAFE,
    schema: asnLookupSchema,
    handler: asnLookup,
    executionMode: 'api',
    tags: ['asn', 'bgp', 'network', 'prefix']
  },
  {
    name: 'vanguard_google_dorks',
    description: 'Generate Google dork queries for a target domain (sensitive files, login pages, etc). SAFE: Generates queries only.',
    category: 'osint',
    permission: PermissionTier.SAFE,
    schema: googleDorksSchema,
    handler: googleDorks,
    executionMode: 'native',
    tags: ['google', 'dorks', 'search', 'discovery']
  },
  {
    name: 'vanguard_shodan_search',
    description: 'Search Shodan for exposed services and vulnerabilities. SAFE: Passive. Requires API key.',
    category: 'osint',
    permission: PermissionTier.SAFE,
    schema: shodanSearchSchema,
    handler: shodanSearch,
    executionMode: 'api',
    tags: ['shodan', 'iot', 'exposed', 'services']
  },
  {
    name: 'vanguard_breach_check',
    description: 'Check if email or domain appeared in known data breaches. SAFE: Passive.',
    category: 'osint',
    permission: PermissionTier.SAFE,
    schema: breachCheckSchema,
    handler: breachCheck,
    executionMode: 'api',
    tags: ['breach', 'haveibeenpwned', 'leak']
  },
  {
    name: 'vanguard_metadata_extract',
    description: 'Extract metadata from web page (emails, tech stack, social links, OG tags). SAFE: Passive.',
    category: 'osint',
    permission: PermissionTier.SAFE,
    schema: metadataExtractSchema,
    handler: metadataExtract,
    executionMode: 'native',
    tags: ['metadata', 'scraping', 'technology']
  },
  {
    name: 'vanguard_dns_history',
    description: 'Lookup historical DNS records for a domain. SAFE: Passive.',
    category: 'osint',
    permission: PermissionTier.SAFE,
    schema: dnsHistorySchema,
    handler: dnsHistory,
    executionMode: 'api',
    tags: ['dns', 'history', 'securitytrails']
  },
  {
    name: 'vanguard_favicon_hash',
    description: 'Calculate favicon hash (MD5, SHA256, MurmurHash3) for Shodan searches. SAFE: Passive.',
    category: 'osint',
    permission: PermissionTier.SAFE,
    schema: faviconHashSchema,
    handler: faviconHash,
    executionMode: 'native',
    tags: ['favicon', 'hash', 'shodan', 'fingerprint']
  },
  {
    name: 'vanguard_web_archive_diff',
    description: 'Search Wayback Machine snapshots and analyze URL history. SAFE: Passive.',
    category: 'osint',
    permission: PermissionTier.SAFE,
    schema: webArchiveDiffSchema,
    handler: webArchiveDiff,
    executionMode: 'api',
    tags: ['wayback', 'archive', 'history', 'diff']
  }
];
