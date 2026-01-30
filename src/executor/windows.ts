import { spawn } from 'child_process';
import { getConfig } from '../config.js';
import { escapeShellArg, sanitizeCommand, SecurityError } from '../utils/sanitizer.js';
import { auditLogger } from '../utils/audit.js';

export interface ExecutionResult {
  success: boolean;
  stdout: string;
  stderr: string;
  exitCode: number | null;
  timedOut: boolean;
}

const COMMAND_ALLOWLIST = new Set([
  'nmap', 'ffuf', 'nuclei', 'where', 'ping', 'tracert',
  'nslookup', 'ipconfig', 'netstat', 'curl', 'powershell'
]);

export async function executeWindows(
  command: string,
  args: string[] = [],
  options: {
    timeout?: number;
    cwd?: string;
    env?: Record<string, string>;
    skipValidation?: boolean;
  } = {}
): Promise<ExecutionResult> {
  const config = getConfig();
  const timeout = options.timeout ?? config.timeout;
  const startTime = Date.now();

  if (!options.skipValidation) {
    const baseCommand = command.split(/[\/\\]/).pop()?.split('.')[0]?.toLowerCase() || command;
    if (!COMMAND_ALLOWLIST.has(baseCommand)) {
      auditLogger.logSecurityEvent('executor', 'blocked_command', { command: baseCommand });
      return {
        success: false,
        stdout: '',
        stderr: `Command not allowed: ${baseCommand}`,
        exitCode: -1,
        timedOut: false
      };
    }
  }

  const safeArgs = args.map(arg => {
    if (arg.startsWith('-') || arg.startsWith('/')) {
      return arg;
    }
    return arg;
  });

  return new Promise((resolve) => {
    let stdout = '';
    let stderr = '';
    let timedOut = false;

    const proc = spawn(command, safeArgs, {
      cwd: options.cwd,
      env: { ...process.env, ...options.env },
      shell: true,
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
      auditLogger.logCommandExecution(command, safeArgs, code, duration);
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

export async function checkCommandExists(command: string): Promise<boolean> {
  const result = await executeWindows('where', [command]);
  return result.success;
}

export async function executeWithRetry(
  command: string,
  args: string[] = [],
  options: {
    timeout?: number;
    cwd?: string;
    env?: Record<string, string>;
    maxRetries?: number;
    retryDelayMs?: number;
  } = {}
): Promise<ExecutionResult> {
  const maxRetries = options.maxRetries ?? 3;
  const retryDelayMs = options.retryDelayMs ?? 1000;

  let lastResult: ExecutionResult | null = null;

  for (let attempt = 0; attempt < maxRetries; attempt++) {
    lastResult = await executeWindows(command, args, options);

    if (lastResult.success) {
      return lastResult;
    }

    if (attempt < maxRetries - 1) {
      await new Promise(resolve => setTimeout(resolve, retryDelayMs));
    }
  }

  return lastResult!;
}
