import { z } from 'zod';

export const certSearchSchema = z.object({
  domain: z.string().describe('Domain to search in certificate transparency logs'),
  includeExpired: z.boolean().default(false).describe('Include expired certificates'),
  includeSubdomains: z.boolean().default(true).describe('Include wildcard subdomains')
});

export type CertSearchInput = z.infer<typeof certSearchSchema>;

interface Certificate {
  id: number;
  issuerName: string;
  commonName: string;
  nameValue: string[];
  notBefore: string;
  notAfter: string;
  serialNumber: string;
  isExpired: boolean;
}

export async function certSearch(input: CertSearchInput): Promise<{
  success: boolean;
  domain: string;
  certificates: Certificate[];
  uniqueDomains: string[];
  stats: {
    total: number;
    expired: number;
    active: number;
    uniqueDomainsCount: number;
  };
  error?: string;
}> {
  const { domain, includeExpired, includeSubdomains } = input;

  try {
    const query = includeSubdomains ? `%.${domain}` : domain;
    const url = `https://crt.sh/?q=${encodeURIComponent(query)}&output=json`;

    const response = await fetch(url, {
      headers: {
        'User-Agent': 'mcp-vanguard/1.0'
      }
    });

    if (!response.ok) {
      return {
        success: false,
        domain,
        certificates: [],
        uniqueDomains: [],
        stats: { total: 0, expired: 0, active: 0, uniqueDomainsCount: 0 },
        error: `crt.sh returned ${response.status}`
      };
    }

    const data = await response.json() as Array<{
      id: number;
      issuer_name: string;
      common_name: string;
      name_value: string;
      not_before: string;
      not_after: string;
      serial_number: string;
    }>;

    const now = new Date();
    const certificates: Certificate[] = [];
    const allDomains = new Set<string>();

    for (const cert of data) {
      const notAfter = new Date(cert.not_after);
      const isExpired = notAfter < now;

      if (!includeExpired && isExpired) {
        continue;
      }

      const nameValues = cert.name_value
        .split('\n')
        .map(n => n.toLowerCase().trim())
        .filter(n => n.length > 0);

      for (const name of nameValues) {
        if (!name.startsWith('*')) {
          allDomains.add(name);
        }
      }

      certificates.push({
        id: cert.id,
        issuerName: cert.issuer_name,
        commonName: cert.common_name,
        nameValue: nameValues,
        notBefore: cert.not_before,
        notAfter: cert.not_after,
        serialNumber: cert.serial_number,
        isExpired
      });
    }

    const uniqueDomains = Array.from(allDomains).sort();
    const expiredCount = certificates.filter(c => c.isExpired).length;

    return {
      success: true,
      domain,
      certificates,
      uniqueDomains,
      stats: {
        total: certificates.length,
        expired: expiredCount,
        active: certificates.length - expiredCount,
        uniqueDomainsCount: uniqueDomains.length
      }
    };
  } catch (err) {
    return {
      success: false,
      domain,
      certificates: [],
      uniqueDomains: [],
      stats: { total: 0, expired: 0, active: 0, uniqueDomainsCount: 0 },
      error: err instanceof Error ? err.message : 'Request failed'
    };
  }
}

export async function getCertificateDetails(certId: number): Promise<{
  success: boolean;
  certificate?: {
    id: number;
    pemData?: string;
    sha256: string;
    sha1: string;
    subject: string;
    issuer: string;
    serialNumber: string;
    validFrom: string;
    validTo: string;
    keyAlgorithm: string;
    keySize: number;
    signatureAlgorithm: string;
    extensions: string[];
  };
  error?: string;
}> {
  try {
    const url = `https://crt.sh/?id=${certId}&output=json`;

    const response = await fetch(url, {
      headers: {
        'User-Agent': 'mcp-vanguard/1.0'
      }
    });

    if (!response.ok) {
      return {
        success: false,
        error: `crt.sh returned ${response.status}`
      };
    }

    const data = await response.json() as {
      id: number;
      sha256: string;
      sha1: string;
      subject: string;
      issuer: string;
      serial_number: string;
      not_before: string;
      not_after: string;
      key_algorithm: string;
      key_size: number;
      signature_algorithm: string;
      extensions?: string;
    };

    return {
      success: true,
      certificate: {
        id: data.id,
        sha256: data.sha256,
        sha1: data.sha1,
        subject: data.subject,
        issuer: data.issuer,
        serialNumber: data.serial_number,
        validFrom: data.not_before,
        validTo: data.not_after,
        keyAlgorithm: data.key_algorithm,
        keySize: data.key_size,
        signatureAlgorithm: data.signature_algorithm,
        extensions: data.extensions ? data.extensions.split('\n') : []
      }
    };
  } catch (err) {
    return {
      success: false,
      error: err instanceof Error ? err.message : 'Request failed'
    };
  }
}

export function analyzeCertificates(certificates: Certificate[]): {
  issuers: Record<string, number>;
  wildcards: string[];
  soonExpiring: Certificate[];
  recentlyIssued: Certificate[];
} {
  const issuers: Record<string, number> = {};
  const wildcards = new Set<string>();
  const soonExpiring: Certificate[] = [];
  const recentlyIssued: Certificate[] = [];

  const now = new Date();
  const thirtyDaysFromNow = new Date(now.getTime() + 30 * 24 * 60 * 60 * 1000);
  const thirtyDaysAgo = new Date(now.getTime() - 30 * 24 * 60 * 60 * 1000);

  for (const cert of certificates) {
    const issuerMatch = cert.issuerName.match(/O=([^,]+)/);
    const issuer = issuerMatch ? issuerMatch[1] : cert.issuerName;
    issuers[issuer] = (issuers[issuer] || 0) + 1;

    for (const name of cert.nameValue) {
      if (name.startsWith('*.')) {
        wildcards.add(name);
      }
    }

    const notAfter = new Date(cert.notAfter);
    if (!cert.isExpired && notAfter < thirtyDaysFromNow) {
      soonExpiring.push(cert);
    }

    const notBefore = new Date(cert.notBefore);
    if (notBefore > thirtyDaysAgo) {
      recentlyIssued.push(cert);
    }
  }

  return {
    issuers,
    wildcards: Array.from(wildcards),
    soonExpiring,
    recentlyIssued
  };
}
