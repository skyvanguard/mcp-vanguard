/**
 * Safe error handling to prevent information leakage
 */

import { maskSensitive, sanitizeOutput } from './sanitizer.js';

export interface SafeError {
  code: string;
  message: string;
  tool?: string;
}

const ERROR_CODES = {
  SCOPE_VIOLATION: 'SCOPE_VIOLATION',
  RATE_LIMITED: 'RATE_LIMITED',
  INVALID_INPUT: 'INVALID_INPUT',
  NETWORK_ERROR: 'NETWORK_ERROR',
  TIMEOUT: 'TIMEOUT',
  COMMAND_FAILED: 'COMMAND_FAILED',
  NOT_FOUND: 'NOT_FOUND',
  PERMISSION_DENIED: 'PERMISSION_DENIED',
  INTERNAL_ERROR: 'INTERNAL_ERROR',
  TOOL_BLOCKED: 'TOOL_BLOCKED',
  SECURITY_ERROR: 'SECURITY_ERROR'
} as const;

export type ErrorCode = typeof ERROR_CODES[keyof typeof ERROR_CODES];

const ERROR_MESSAGES: Record<ErrorCode, string> = {
  SCOPE_VIOLATION: 'Target is not in the authorized scope',
  RATE_LIMITED: 'Rate limit exceeded, please wait before retrying',
  INVALID_INPUT: 'Invalid input provided',
  NETWORK_ERROR: 'Network request failed',
  TIMEOUT: 'Operation timed out',
  COMMAND_FAILED: 'Command execution failed',
  NOT_FOUND: 'Resource not found',
  PERMISSION_DENIED: 'Permission denied',
  INTERNAL_ERROR: 'An internal error occurred',
  TOOL_BLOCKED: 'This tool is blocked for security reasons',
  SECURITY_ERROR: 'Security policy violation'
};

export function createSafeError(code: ErrorCode, tool?: string, details?: string): SafeError {
  return {
    code,
    message: ERROR_MESSAGES[code] + (details ? `: ${sanitizeErrorDetails(details)}` : ''),
    tool
  };
}

export function toSafeError(error: unknown, tool?: string): SafeError {
  if (error instanceof Error) {
    const code = mapErrorToCode(error);
    const safeMessage = sanitizeErrorMessage(error.message);

    return {
      code,
      message: safeMessage,
      tool
    };
  }

  return createSafeError('INTERNAL_ERROR', tool);
}

function mapErrorToCode(error: Error): ErrorCode {
  const message = error.message.toLowerCase();
  const name = error.name.toLowerCase();

  if (name === 'securityerror' || message.includes('security')) {
    return 'SECURITY_ERROR';
  }

  if (message.includes('scope') || message.includes('not in scope')) {
    return 'SCOPE_VIOLATION';
  }

  if (message.includes('rate limit') || message.includes('too many requests')) {
    return 'RATE_LIMITED';
  }

  if (message.includes('timeout') || message.includes('timed out') || name === 'aborterror') {
    return 'TIMEOUT';
  }

  if (message.includes('enotfound') || message.includes('network') ||
      message.includes('fetch failed') || message.includes('econnrefused')) {
    return 'NETWORK_ERROR';
  }

  if (message.includes('not found') || message.includes('404')) {
    return 'NOT_FOUND';
  }

  if (message.includes('permission') || message.includes('access denied') ||
      message.includes('forbidden') || message.includes('403')) {
    return 'PERMISSION_DENIED';
  }

  if (message.includes('invalid') || message.includes('validation')) {
    return 'INVALID_INPUT';
  }

  if (message.includes('command') || message.includes('exec') || message.includes('spawn')) {
    return 'COMMAND_FAILED';
  }

  return 'INTERNAL_ERROR';
}

function sanitizeErrorMessage(message: string): string {
  let safe = message;

  safe = safe.replace(/([a-zA-Z]:)?[\/\\][\w\-. \/\\]+/g, '[path]');

  safe = safe.replace(/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/g, '[ip]');

  safe = safe.replace(/:\d+\b/g, ':[port]');

  safe = safe.replace(/at\s+[\w.]+\s+\([^)]+\)/g, '');
  safe = safe.replace(/at\s+[^\n]+/g, '');

  safe = safe.replace(/\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g, '[email]');

  if (safe.length > 200) {
    safe = safe.slice(0, 200) + '...';
  }

  return safe.trim() || 'An error occurred';
}

function sanitizeErrorDetails(details: string): string {
  return sanitizeErrorMessage(details);
}

export function wrapError<T>(
  fn: () => Promise<T>,
  tool: string
): Promise<T> {
  return fn().catch(error => {
    throw toSafeError(error, tool);
  });
}

export function formatSafeError(error: SafeError): string {
  return JSON.stringify({
    success: false,
    error: {
      code: error.code,
      message: error.message
    }
  }, null, 2);
}

export class ToolError extends Error {
  code: ErrorCode;
  tool?: string;

  constructor(code: ErrorCode, tool?: string, details?: string) {
    const safe = createSafeError(code, tool, details);
    super(safe.message);
    this.name = 'ToolError';
    this.code = code;
    this.tool = tool;
  }

  toSafeError(): SafeError {
    return {
      code: this.code,
      message: this.message,
      tool: this.tool
    };
  }
}
