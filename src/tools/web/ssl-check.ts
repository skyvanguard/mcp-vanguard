import { z } from 'zod';

export const sslCheckSchema = z.object({
  host: z.string().describe('Hostname to check SSL/TLS certificate'),
  port: z.number().default(443).describe('Port number'),
  timeout: z.number().default(10000).describe('Connection timeout in ms')
});

export type SslCheckInput = z.infer<typeof sslCheckSchema>;

interface SslResult {
  host: string;
  port: number;
  valid: boolean;
  issuer: string;
  subject: string;
  validFrom: string;
  validTo: string;
  daysUntilExpiry: number;
  serialNumber: string;
  fingerprint: string;
  protocol: string;
  cipher: string;
  keySize: number;
  san: string[];
  issues: SslIssue[];
  grade: string;
}

interface SslIssue {
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  title: string;
  description: string;
}

export async function sslCheck(input: SslCheckInput): Promise<{
  success: boolean;
  result: SslResult | null;
  error?: string;
}> {
  const { host, port, timeout } = input;

  try {
    const tls = await import('tls');
    const { promisify } = await import('util');

    return new Promise((resolve) => {
      const issues: SslIssue[] = [];

      const socket = tls.connect({
        host,
        port,
        servername: host,
        rejectUnauthorized: false,
        timeout
      }, () => {
        const cert = socket.getPeerCertificate(true);
        const cipher = socket.getCipher();
        const protocol = socket.getProtocol();

        if (!cert || !cert.subject) {
          socket.destroy();
          resolve({
            success: false,
            result: null,
            error: 'Could not retrieve certificate'
          });
          return;
        }

        const validFrom = new Date(cert.valid_from);
        const validTo = new Date(cert.valid_to);
        const now = new Date();
        const daysUntilExpiry = Math.floor((validTo.getTime() - now.getTime()) / (1000 * 60 * 60 * 24));

        if (!socket.authorized) {
          issues.push({
            severity: 'critical',
            title: 'Certificate Not Trusted',
            description: String(socket.authorizationError) || 'Certificate chain validation failed'
          });
        }

        if (daysUntilExpiry < 0) {
          issues.push({
            severity: 'critical',
            title: 'Certificate Expired',
            description: `Certificate expired ${Math.abs(daysUntilExpiry)} days ago`
          });
        } else if (daysUntilExpiry < 7) {
          issues.push({
            severity: 'critical',
            title: 'Certificate Expiring Soon',
            description: `Certificate expires in ${daysUntilExpiry} days`
          });
        } else if (daysUntilExpiry < 30) {
          issues.push({
            severity: 'high',
            title: 'Certificate Expiring Soon',
            description: `Certificate expires in ${daysUntilExpiry} days`
          });
        }

        if (protocol === 'TLSv1' || protocol === 'TLSv1.1') {
          issues.push({
            severity: 'high',
            title: 'Deprecated TLS Version',
            description: `Using ${protocol} which is deprecated. Upgrade to TLS 1.2 or 1.3`
          });
        } else if (protocol === 'SSLv3') {
          issues.push({
            severity: 'critical',
            title: 'Insecure SSL Version',
            description: 'SSLv3 is vulnerable to POODLE attack'
          });
        }

        const weakCiphers = ['RC4', 'DES', '3DES', 'MD5', 'NULL', 'EXPORT', 'anon'];
        if (cipher && weakCiphers.some(weak => cipher.name.includes(weak))) {
          issues.push({
            severity: 'high',
            title: 'Weak Cipher Suite',
            description: `Using weak cipher: ${cipher.name}`
          });
        }

        if (cipher && cipher.name.includes('CBC') && (protocol === 'TLSv1' || protocol === 'TLSv1.1')) {
          issues.push({
            severity: 'medium',
            title: 'CBC Mode Cipher',
            description: 'CBC ciphers with TLS 1.0/1.1 may be vulnerable to BEAST attack'
          });
        }

        const keySize = cert.bits || 0;
        if (keySize > 0 && keySize < 2048) {
          issues.push({
            severity: 'high',
            title: 'Weak Key Size',
            description: `Key size ${keySize} bits is too small. Minimum recommended is 2048 bits`
          });
        }

        const san = cert.subjectaltname
          ? cert.subjectaltname.split(', ').map((s: string) => s.replace('DNS:', ''))
          : [];

        const subjectCN = cert.subject.CN || '';
        if (!san.includes(host) && subjectCN !== host && !san.some((s: string) => matchWildcard(s, host))) {
          issues.push({
            severity: 'high',
            title: 'Hostname Mismatch',
            description: `Certificate does not match hostname ${host}`
          });
        }

        if (cert.issuer && cert.issuer.CN === cert.subject.CN) {
          issues.push({
            severity: 'medium',
            title: 'Self-Signed Certificate',
            description: 'Certificate is self-signed and will not be trusted by browsers'
          });
        }

        const grade = calculateGrade(issues, protocol || '', daysUntilExpiry);

        socket.destroy();

        resolve({
          success: true,
          result: {
            host,
            port,
            valid: socket.authorized,
            issuer: formatDN(cert.issuer),
            subject: formatDN(cert.subject),
            validFrom: validFrom.toISOString(),
            validTo: validTo.toISOString(),
            daysUntilExpiry,
            serialNumber: cert.serialNumber,
            fingerprint: cert.fingerprint256 || cert.fingerprint,
            protocol: protocol || 'unknown',
            cipher: cipher ? cipher.name : 'unknown',
            keySize,
            san,
            issues,
            grade
          }
        });
      });

      socket.on('error', (err) => {
        resolve({
          success: false,
          result: null,
          error: err.message
        });
      });

      socket.on('timeout', () => {
        socket.destroy();
        resolve({
          success: false,
          result: null,
          error: 'Connection timeout'
        });
      });
    });
  } catch (err) {
    return {
      success: false,
      result: null,
      error: err instanceof Error ? err.message : 'SSL check failed'
    };
  }
}

function formatDN(dn: { CN?: string; O?: string; C?: string } | null | undefined): string {
  if (!dn) return 'Unknown';
  const parts = [];
  if (dn.CN) parts.push(`CN=${dn.CN}`);
  if (dn.O) parts.push(`O=${dn.O}`);
  if (dn.C) parts.push(`C=${dn.C}`);
  return parts.join(', ') || 'Unknown';
}

function matchWildcard(pattern: string, hostname: string): boolean {
  if (!pattern.startsWith('*.')) return pattern === hostname;
  const suffix = pattern.slice(2);
  return hostname.endsWith(suffix) && hostname.split('.').length === pattern.split('.').length;
}

function calculateGrade(issues: SslIssue[], protocol: string, daysUntilExpiry: number): string {
  let score = 100;

  for (const issue of issues) {
    switch (issue.severity) {
      case 'critical': score -= 40; break;
      case 'high': score -= 25; break;
      case 'medium': score -= 10; break;
      case 'low': score -= 5; break;
    }
  }

  if (protocol === 'TLSv1.3') score += 5;

  score = Math.max(0, Math.min(100, score));

  if (score >= 90) return 'A+';
  if (score >= 80) return 'A';
  if (score >= 70) return 'B';
  if (score >= 60) return 'C';
  if (score >= 50) return 'D';
  return 'F';
}
