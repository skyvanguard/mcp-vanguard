import { z } from 'zod';

export const attackSurfaceSchema = z.object({
  target: z.string().describe('Target domain or IP'),
  openPorts: z.array(z.number()).optional().describe('Known open ports'),
  technologies: z.array(z.string()).optional().describe('Known technologies (e.g., "Apache", "PHP", "WordPress")'),
  subdomains: z.array(z.string()).optional().describe('Known subdomains'),
  exposedServices: z.array(z.string()).optional().describe('Exposed services (e.g., "FTP", "SSH", "RDP")'),
});

export type AttackSurfaceInput = z.infer<typeof attackSurfaceSchema>;

interface SurfaceEntry {
  category: string;
  asset: string;
  risk: 'critical' | 'high' | 'medium' | 'low' | 'info';
  suggestedTests: string[];
}

export async function attackSurface(input: AttackSurfaceInput): Promise<{
  success: boolean;
  target: string;
  surface: SurfaceEntry[];
  totalAssets: number;
  riskBreakdown: Record<string, number>;
  recommendedTools: string[];
}> {
  const { target, openPorts = [], technologies = [], subdomains = [], exposedServices = [] } = input;
  const surface: SurfaceEntry[] = [];
  const recommendedTools = new Set<string>();

  // Analyze ports
  for (const port of openPorts) {
    const portInfo = getPortInfo(port);
    surface.push({
      category: 'network',
      asset: `${target}:${port} (${portInfo.service})`,
      risk: portInfo.risk,
      suggestedTests: portInfo.tests,
    });
    portInfo.tools.forEach(t => recommendedTools.add(t));
  }

  // Analyze technologies
  for (const tech of technologies) {
    const techInfo = getTechInfo(tech);
    surface.push({
      category: 'technology',
      asset: tech,
      risk: techInfo.risk,
      suggestedTests: techInfo.tests,
    });
    techInfo.tools.forEach(t => recommendedTools.add(t));
  }

  // Analyze subdomains
  for (const sub of subdomains) {
    surface.push({
      category: 'subdomain',
      asset: sub,
      risk: 'medium',
      suggestedTests: ['Subdomain takeover check', 'Port scan', 'Technology fingerprint'],
    });
    recommendedTools.add('vanguard_subdomain_takeover');
    recommendedTools.add('vanguard_port_scan');
  }

  // Analyze services
  for (const svc of exposedServices) {
    const svcInfo = getServiceInfo(svc);
    surface.push({
      category: 'service',
      asset: svc,
      risk: svcInfo.risk,
      suggestedTests: svcInfo.tests,
    });
    svcInfo.tools.forEach(t => recommendedTools.add(t));
  }

  // Always recommend basics
  recommendedTools.add('vanguard_headers_check');
  recommendedTools.add('vanguard_crypto_audit');

  const riskBreakdown: Record<string, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const s of surface) riskBreakdown[s.risk]++;

  return {
    success: true,
    target,
    surface,
    totalAssets: surface.length,
    riskBreakdown,
    recommendedTools: [...recommendedTools],
  };
}

function getPortInfo(port: number): { service: string; risk: 'critical' | 'high' | 'medium' | 'low' | 'info'; tests: string[]; tools: string[] } {
  const portMap: Record<number, { service: string; risk: 'critical' | 'high' | 'medium' | 'low' | 'info'; tests: string[]; tools: string[] }> = {
    21: { service: 'FTP', risk: 'high', tests: ['Anonymous login', 'Banner grab'], tools: ['vanguard_ftp_check', 'vanguard_banner_grab'] },
    22: { service: 'SSH', risk: 'medium', tests: ['SSH audit', 'Weak auth'], tools: ['vanguard_ssh_audit'] },
    23: { service: 'Telnet', risk: 'critical', tests: ['Cleartext credentials', 'Banner grab'], tools: ['vanguard_banner_grab'] },
    25: { service: 'SMTP', risk: 'medium', tests: ['Open relay', 'User enumeration'], tools: ['vanguard_banner_grab'] },
    80: { service: 'HTTP', risk: 'medium', tests: ['Web scan', 'Directory fuzzing', 'Vuln scan'], tools: ['vanguard_ffuf', 'vanguard_nuclei_scan'] },
    443: { service: 'HTTPS', risk: 'low', tests: ['TLS audit', 'Web scan'], tools: ['vanguard_crypto_audit', 'vanguard_nuclei_scan'] },
    445: { service: 'SMB', risk: 'high', tests: ['SMB enum', 'Null session'], tools: ['vanguard_smb_enum'] },
    1433: { service: 'MSSQL', risk: 'high', tests: ['Default creds', 'SQLi'], tools: ['vanguard_sqli_test'] },
    3306: { service: 'MySQL', risk: 'high', tests: ['Default creds', 'Remote access'], tools: ['vanguard_banner_grab'] },
    3389: { service: 'RDP', risk: 'high', tests: ['NLA check', 'BlueKeep'], tools: ['vanguard_port_scan'] },
    5432: { service: 'PostgreSQL', risk: 'high', tests: ['Default creds', 'Trust auth'], tools: ['vanguard_banner_grab'] },
    6379: { service: 'Redis', risk: 'critical', tests: ['No-auth access', 'RCE'], tools: ['vanguard_banner_grab'] },
    8080: { service: 'HTTP-Alt', risk: 'medium', tests: ['Web scan', 'Admin panel'], tools: ['vanguard_ffuf'] },
    27017: { service: 'MongoDB', risk: 'critical', tests: ['No-auth access', 'Data dump'], tools: ['vanguard_banner_grab'] },
  };
  return portMap[port] || { service: `Unknown (${port})`, risk: 'info', tests: ['Banner grab', 'Service detection'], tools: ['vanguard_service_detect'] };
}

function getTechInfo(tech: string): { risk: 'critical' | 'high' | 'medium' | 'low' | 'info'; tests: string[]; tools: string[] } {
  const lower = tech.toLowerCase();
  if (lower.includes('wordpress')) return { risk: 'medium', tests: ['WPScan', 'Plugin vulns', 'User enum'], tools: ['vanguard_nuclei_scan', 'vanguard_ffuf'] };
  if (lower.includes('php')) return { risk: 'medium', tests: ['LFI', 'RCE', 'Deserialization'], tools: ['vanguard_lfi_test', 'vanguard_deserialization_check'] };
  if (lower.includes('java') || lower.includes('tomcat')) return { risk: 'medium', tests: ['Deserialization', 'Log4j', 'Manager access'], tools: ['vanguard_deserialization_check', 'vanguard_nuclei_scan'] };
  if (lower.includes('node') || lower.includes('express')) return { risk: 'low', tests: ['Prototype pollution', 'SSRF'], tools: ['vanguard_ssrf_test'] };
  return { risk: 'info', tests: ['Version check', 'CVE lookup'], tools: ['vanguard_cve_lookup'] };
}

function getServiceInfo(svc: string): { risk: 'critical' | 'high' | 'medium' | 'low' | 'info'; tests: string[]; tools: string[] } {
  const lower = svc.toLowerCase();
  if (lower.includes('ftp')) return { risk: 'high', tests: ['Anonymous login'], tools: ['vanguard_ftp_check'] };
  if (lower.includes('ssh')) return { risk: 'medium', tests: ['SSH audit'], tools: ['vanguard_ssh_audit'] };
  if (lower.includes('rdp')) return { risk: 'high', tests: ['NLA check'], tools: ['vanguard_port_scan'] };
  if (lower.includes('smb')) return { risk: 'high', tests: ['SMB enum'], tools: ['vanguard_smb_enum'] };
  if (lower.includes('docker')) return { risk: 'critical', tests: ['Docker socket'], tools: ['vanguard_docker_socket'] };
  return { risk: 'info', tests: ['Banner grab'], tools: ['vanguard_banner_grab'] };
}
