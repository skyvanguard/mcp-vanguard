/**
 * Input sanitization utilities to prevent injection attacks
 */

const DANGEROUS_CHARS = /[;&|`$(){}[\]<>\\!]/g;
const SHELL_METACHARACTERS = /[;&|`$(){}[\]<>\\!\n\r]/g;
const PATH_TRAVERSAL = /\.\.[\/\\]/g;

export function sanitizeForShell(input: string): string {
  if (!input) return '';
  return input.replace(SHELL_METACHARACTERS, '');
}

export function sanitizeDomain(domain: string): string {
  if (!domain) return '';

  let sanitized = domain.toLowerCase().trim();

  sanitized = sanitized.replace(/^https?:\/\//, '');
  sanitized = sanitized.replace(/\/.*$/, '');
  sanitized = sanitized.replace(/:\d+$/, '');

  if (!isValidDomain(sanitized) && !isValidIP(sanitized)) {
    throw new SecurityError(`Invalid domain format: ${maskSensitive(domain)}`);
  }

  return sanitized;
}

export function sanitizeUrl(url: string): string {
  if (!url) return '';

  try {
    const parsed = new URL(url);

    if (!['http:', 'https:'].includes(parsed.protocol)) {
      throw new SecurityError('Only HTTP/HTTPS protocols are allowed');
    }

    if (parsed.username || parsed.password) {
      throw new SecurityError('URLs with credentials are not allowed');
    }

    if (isPrivateIP(parsed.hostname)) {
      throw new SecurityError('Private/internal IPs are not allowed');
    }

    return parsed.toString();
  } catch (err) {
    if (err instanceof SecurityError) throw err;
    throw new SecurityError(`Invalid URL format: ${maskSensitive(url)}`);
  }
}

export function sanitizePath(path: string): string {
  if (!path) return '';

  if (PATH_TRAVERSAL.test(path)) {
    throw new SecurityError('Path traversal detected');
  }

  return path.replace(/\\/g, '/');
}

export function sanitizeCommand(command: string): string {
  if (!command) return '';

  const allowedCommands = [
    'nmap', 'ffuf', 'nuclei', 'whois', 'dig', 'host',
    'curl', 'wget', 'ping', 'traceroute'
  ];

  const baseCommand = command.split(/\s+/)[0].toLowerCase();

  if (!allowedCommands.includes(baseCommand)) {
    throw new SecurityError(`Command not in allowlist: ${baseCommand}`);
  }

  return command;
}

export function escapeShellArg(arg: string): string {
  if (!arg) return "''";

  if (process.platform === 'win32') {
    return `"${arg.replace(/"/g, '""').replace(/%/g, '%%')}"`;
  }

  if (!/[^a-zA-Z0-9_\-.,/:@]/.test(arg)) {
    return arg;
  }

  return `'${arg.replace(/'/g, "'\\''")}'`;
}

export function escapeShellArgs(args: string[]): string[] {
  return args.map(escapeShellArg);
}

export function sanitizeForRegex(input: string): string {
  return input.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

export function isValidDomain(domain: string): boolean {
  if (!domain || domain.length > 253) return false;

  const domainRegex = /^(\*\.)?[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*$/i;
  return domainRegex.test(domain);
}

export function isValidIP(ip: string): boolean {
  const ipv4Regex = /^(\d{1,3}\.){3}\d{1,3}$/;
  const ipv6Regex = /^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$/;

  if (ipv4Regex.test(ip)) {
    const parts = ip.split('.').map(Number);
    return parts.every(p => p >= 0 && p <= 255);
  }

  return ipv6Regex.test(ip);
}

export function isPrivateIP(ip: string): boolean {
  if (!isValidIP(ip)) return false;

  const parts = ip.split('.').map(Number);

  if (parts[0] === 10) return true;
  if (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) return true;
  if (parts[0] === 192 && parts[1] === 168) return true;
  if (parts[0] === 127) return true;
  if (parts[0] === 0) return true;
  if (parts[0] === 169 && parts[1] === 254) return true;

  return false;
}

export function maskSensitive(value: string): string {
  if (!value || value.length <= 4) return '****';

  const visible = Math.min(4, Math.floor(value.length / 4));
  return value.slice(0, visible) + '****' + value.slice(-visible);
}

export function sanitizeOutput(output: string): string {
  let sanitized = output;

  const patterns = [
    /([a-zA-Z]:)?[\/\\][\w\-. \/\\]+/g,
    /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g,
    /AKIA[0-9A-Z]{16}/g,
    /ghp_[A-Za-z0-9_]{36,}/g,
    /sk_live_[A-Za-z0-9]{24,}/g,
    /eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*/g,
  ];

  for (const pattern of patterns) {
    sanitized = sanitized.replace(pattern, '[REDACTED]');
  }

  return sanitized;
}

export class SecurityError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'SecurityError';
  }
}

export function validateInput<T>(
  input: T,
  validators: Array<(input: T) => void>
): T {
  for (const validator of validators) {
    validator(input);
  }
  return input;
}
