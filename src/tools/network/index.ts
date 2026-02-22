import { PermissionTier } from '../../config.js';
import { ToolDefinition } from '../../types/tool.js';
import { tracerouteSchema, traceroute } from './traceroute.js';
import { pingSweepSchema, pingSweep } from './ping-sweep.js';
import { serviceDetectSchema, serviceDetect } from './service-detect.js';
import { osDetectSchema, osDetect } from './os-detect.js';
import { bannerGrabSchema, bannerGrab } from './banner-grab.js';
import { snmpEnumSchema, snmpEnum } from './snmp-enum.js';
import { smbEnumSchema, smbEnum } from './smb-enum.js';
import { ldapEnumSchema, ldapEnum } from './ldap-enum.js';
import { ftpCheckSchema, ftpCheck } from './ftp-check.js';
import { sshAuditSchema, sshAudit } from './ssh-audit.js';
import { dnsZoneTransferSchema, dnsZoneTransfer } from './dns-zone-transfer.js';
import { reverseDnsSchema, reverseDnsLookup } from './reverse-dns.js';
import { arpScanSchema, arpScan } from './arp-scan.js';
import { networkCidrSchema, networkCidr } from './network-cidr.js';
import { httpMethodsSchema, httpMethods } from './http-methods.js';

export const networkTools: ToolDefinition[] = [
  {
    name: 'vanguard_traceroute',
    description: 'Trace network path to target showing each hop. DANGEROUS: Active probing.',
    category: 'network',
    permission: PermissionTier.DANGEROUS,
    schema: tracerouteSchema,
    handler: traceroute,
    executionMode: 'hybrid',
    wslCommands: ['traceroute'],
    windowsCommands: ['tracert'],
    requiresScope: true,
    tags: ['traceroute', 'network', 'path']
  },
  {
    name: 'vanguard_ping_sweep',
    description: 'Discover live hosts in a network range using ICMP. DANGEROUS: Active scanning.',
    category: 'network',
    permission: PermissionTier.DANGEROUS,
    schema: pingSweepSchema,
    handler: pingSweep,
    executionMode: 'hybrid',
    wslCommands: ['nmap'],
    windowsCommands: ['nmap'],
    requiresScope: true,
    tags: ['ping', 'sweep', 'discovery', 'hosts']
  },
  {
    name: 'vanguard_service_detect',
    description: 'Detect services and versions running on open ports using nmap -sV. DANGEROUS: Active probing.',
    category: 'network',
    permission: PermissionTier.DANGEROUS,
    schema: serviceDetectSchema,
    handler: serviceDetect,
    executionMode: 'hybrid',
    wslCommands: ['nmap'],
    windowsCommands: ['nmap'],
    requiresScope: true,
    tags: ['service', 'version', 'detection', 'nmap']
  },
  {
    name: 'vanguard_os_detect',
    description: 'Detect operating system using nmap OS fingerprinting. DANGEROUS: Active probing. Requires root/admin.',
    category: 'network',
    permission: PermissionTier.DANGEROUS,
    schema: osDetectSchema,
    handler: osDetect,
    executionMode: 'hybrid',
    wslCommands: ['nmap'],
    windowsCommands: ['nmap'],
    requiresScope: true,
    tags: ['os', 'detection', 'fingerprint', 'nmap']
  },
  {
    name: 'vanguard_banner_grab',
    description: 'Grab service banners from open ports via TCP connection. DANGEROUS: Active probing.',
    category: 'network',
    permission: PermissionTier.DANGEROUS,
    schema: bannerGrabSchema,
    handler: bannerGrab,
    executionMode: 'native',
    requiresScope: true,
    tags: ['banner', 'grab', 'service']
  },
  {
    name: 'vanguard_snmp_enum',
    description: 'Enumerate SNMP data (system info, interfaces, routes). DANGEROUS: Active enumeration. Requires WSL.',
    category: 'network',
    permission: PermissionTier.DANGEROUS,
    schema: snmpEnumSchema,
    handler: snmpEnum,
    executionMode: 'wsl',
    wslCommands: ['snmpwalk'],
    requiresScope: true,
    tags: ['snmp', 'enumeration', 'network']
  },
  {
    name: 'vanguard_smb_enum',
    description: 'Enumerate SMB shares, users, and OS info. DANGEROUS: Active enumeration. Requires WSL.',
    category: 'network',
    permission: PermissionTier.DANGEROUS,
    schema: smbEnumSchema,
    handler: smbEnum,
    executionMode: 'wsl',
    wslCommands: ['smbclient', 'enum4linux'],
    requiresScope: true,
    tags: ['smb', 'shares', 'enumeration', 'windows']
  },
  {
    name: 'vanguard_ldap_enum',
    description: 'Enumerate LDAP directory (users, groups, OUs). DANGEROUS: Active enumeration. Requires WSL.',
    category: 'network',
    permission: PermissionTier.DANGEROUS,
    schema: ldapEnumSchema,
    handler: ldapEnum,
    executionMode: 'wsl',
    wslCommands: ['ldapsearch'],
    requiresScope: true,
    tags: ['ldap', 'directory', 'enumeration', 'ad']
  },
  {
    name: 'vanguard_ftp_check',
    description: 'Check FTP server for anonymous access, banner, and features. SAFE: Passive check.',
    category: 'network',
    permission: PermissionTier.SAFE,
    schema: ftpCheckSchema,
    handler: ftpCheck,
    executionMode: 'native',
    requiresScope: true,
    tags: ['ftp', 'anonymous', 'check']
  },
  {
    name: 'vanguard_ssh_audit',
    description: 'Audit SSH server configuration (algorithms, protocol, vulnerabilities). SAFE: Passive analysis.',
    category: 'network',
    permission: PermissionTier.SAFE,
    schema: sshAuditSchema,
    handler: sshAudit,
    executionMode: 'hybrid',
    wslCommands: ['ssh-audit'],
    requiresScope: true,
    tags: ['ssh', 'audit', 'security']
  },
  {
    name: 'vanguard_dns_zone_transfer',
    description: 'Attempt DNS zone transfer (AXFR) to discover all records. DANGEROUS: Active reconnaissance.',
    category: 'network',
    permission: PermissionTier.DANGEROUS,
    schema: dnsZoneTransferSchema,
    handler: dnsZoneTransfer,
    executionMode: 'hybrid',
    wslCommands: ['dig'],
    windowsCommands: ['nslookup'],
    requiresScope: true,
    tags: ['dns', 'zone-transfer', 'axfr']
  },
  {
    name: 'vanguard_reverse_dns',
    description: 'Reverse DNS lookup (PTR record) for an IP address. SAFE: Passive DNS query.',
    category: 'network',
    permission: PermissionTier.SAFE,
    schema: reverseDnsSchema,
    handler: reverseDnsLookup,
    executionMode: 'api',
    tags: ['dns', 'reverse', 'ptr']
  },
  {
    name: 'vanguard_arp_scan',
    description: 'Discover hosts on local network using ARP requests. DANGEROUS: Active scanning. Requires WSL root.',
    category: 'network',
    permission: PermissionTier.DANGEROUS,
    schema: arpScanSchema,
    handler: arpScan,
    executionMode: 'wsl',
    wslCommands: ['arp-scan'],
    requiresScope: true,
    tags: ['arp', 'scan', 'local', 'discovery']
  },
  {
    name: 'vanguard_network_cidr',
    description: 'CIDR calculator: subnet info, expand IP ranges, check containment. SAFE: Offline utility.',
    category: 'network',
    permission: PermissionTier.SAFE,
    schema: networkCidrSchema,
    handler: networkCidr,
    executionMode: 'native',
    tags: ['cidr', 'subnet', 'calculator', 'network']
  },
  {
    name: 'vanguard_http_methods',
    description: 'Test which HTTP methods are allowed on a URL (GET, PUT, DELETE, TRACE, etc). SAFE: Passive analysis.',
    category: 'network',
    permission: PermissionTier.SAFE,
    schema: httpMethodsSchema,
    handler: httpMethods,
    executionMode: 'native',
    requiresScope: true,
    tags: ['http', 'methods', 'allowed', 'security']
  }
];
