import { spawn } from 'child_process';
import { getConfig } from '../config.js';
import { ExecutionResult } from './windows.js';
import { escapeShellArg } from '../utils/sanitizer.js';
import { auditLogger } from '../utils/audit.js';

const WSL_COMMAND_ALLOWLIST = new Set([
  'nmap', 'ffuf', 'nuclei', 'whois', 'dig', 'host',
  'curl', 'wget', 'ping', 'traceroute', 'which', 'echo'
]);

export async function executeWSL(
  command: string,
  args: string[] = [],
  options: {
    timeout?: number;
    cwd?: string;
    env?: Record<string, string>;
    distro?: string;
    skipValidation?: boolean;
  } = {}
): Promise<ExecutionResult> {
  const config = getConfig();
  const timeout = options.timeout ?? config.timeout;
  const distro = options.distro ?? config.wslDistro;
  const startTime = Date.now();

  if (!options.skipValidation) {
    const baseCommand = command.split('/').pop()?.toLowerCase() || command;
    if (!WSL_COMMAND_ALLOWLIST.has(baseCommand)) {
      auditLogger.logSecurityEvent('wsl_executor', 'blocked_command', { command: baseCommand });
      return {
        success: false,
        stdout: '',
        stderr: `Command not allowed in WSL: ${baseCommand}`,
        exitCode: -1,
        timedOut: false
      };
    }
  }

  const safeArgs = args.map(arg => escapeShellArg(arg));
  const fullCommand = `${command} ${safeArgs.join(' ')}`;

  const wslArgs = ['-d', distro, '--', 'bash', '-c', fullCommand];

  return new Promise((resolve) => {
    let stdout = '';
    let stderr = '';
    let timedOut = false;

    const proc = spawn('wsl', wslArgs, {
      cwd: options.cwd,
      env: { ...process.env, ...options.env },
      windowsHide: true
    });

    const timeoutId = setTimeout(() => {
      timedOut = true;
      proc.kill('SIGTERM');
    }, timeout);

    proc.stdout.on('data', (data) => {
      stdout += data.toString();
    });

    proc.stderr.on('data', (data) => {
      stderr += data.toString();
    });

    proc.on('close', (code) => {
      clearTimeout(timeoutId);
      const duration = Date.now() - startTime;
      auditLogger.logCommandExecution(`wsl:${command}`, safeArgs, code, duration);
      resolve({
        success: code === 0 && !timedOut,
        stdout: stdout.trim(),
        stderr: stderr.trim(),
        exitCode: code,
        timedOut
      });
    });

    proc.on('error', (err) => {
      clearTimeout(timeoutId);
      resolve({
        success: false,
        stdout: '',
        stderr: err.message,
        exitCode: null,
        timedOut: false
      });
    });
  });
}

export async function checkWSLAvailable(): Promise<boolean> {
  return new Promise((resolve) => {
    const proc = spawn('wsl', ['--list', '--quiet'], {
      windowsHide: true
    });

    proc.on('close', (code) => {
      resolve(code === 0);
    });

    proc.on('error', () => {
      resolve(false);
    });
  });
}

export async function checkWSLDistroAvailable(distro: string): Promise<boolean> {
  return new Promise((resolve) => {
    const proc = spawn('wsl', ['-d', distro, '--', 'echo', 'ok'], {
      windowsHide: true
    });

    let output = '';
    proc.stdout.on('data', (data) => {
      output += data.toString();
    });

    proc.on('close', (code) => {
      resolve(code === 0 && output.includes('ok'));
    });

    proc.on('error', () => {
      resolve(false);
    });
  });
}

export async function checkWSLCommandExists(
  command: string,
  distro?: string
): Promise<boolean> {
  const config = getConfig();
  const targetDistro = distro ?? config.wslDistro;

  const result = await executeWSL('which', [command], { distro: targetDistro });
  return result.success && result.stdout.length > 0;
}

export function convertWindowsPathToWSL(windowsPath: string): string {
  const normalizedPath = windowsPath.replace(/\\/g, '/');

  const driveMatch = normalizedPath.match(/^([a-zA-Z]):/);
  if (driveMatch) {
    const driveLetter = driveMatch[1].toLowerCase();
    const restOfPath = normalizedPath.slice(2);
    return `/mnt/${driveLetter}${restOfPath}`;
  }

  return normalizedPath;
}

export function convertWSLPathToWindows(wslPath: string): string {
  const mntMatch = wslPath.match(/^\/mnt\/([a-z])\//);
  if (mntMatch) {
    const driveLetter = mntMatch[1].toUpperCase();
    const restOfPath = wslPath.slice(7).replace(/\//g, '\\');
    return `${driveLetter}:\\${restOfPath}`;
  }

  return wslPath;
}
