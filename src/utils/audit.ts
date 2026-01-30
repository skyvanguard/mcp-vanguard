/**
 * Audit logging for security-sensitive operations
 */

export enum AuditLevel {
  INFO = 'INFO',
  WARN = 'WARN',
  ERROR = 'ERROR',
  SECURITY = 'SECURITY'
}

export interface AuditEntry {
  timestamp: string;
  level: AuditLevel;
  tool: string;
  action: string;
  target?: string;
  result: 'success' | 'failure' | 'blocked';
  details?: Record<string, unknown>;
  error?: string;
  duration?: number;
}

class AuditLogger {
  private entries: AuditEntry[] = [];
  private maxEntries: number = 1000;
  private enabled: boolean = true;

  enable(): void {
    this.enabled = true;
  }

  disable(): void {
    this.enabled = false;
  }

  log(entry: Omit<AuditEntry, 'timestamp'>): void {
    if (!this.enabled) return;

    const fullEntry: AuditEntry = {
      ...entry,
      timestamp: new Date().toISOString()
    };

    this.entries.push(fullEntry);

    if (this.entries.length > this.maxEntries) {
      this.entries.shift();
    }

    if (entry.level === AuditLevel.SECURITY || entry.level === AuditLevel.ERROR) {
      this.logToConsole(fullEntry);
    }
  }

  logToolCall(
    tool: string,
    target: string | undefined,
    result: 'success' | 'failure' | 'blocked',
    details?: Record<string, unknown>,
    error?: string,
    duration?: number
  ): void {
    this.log({
      level: result === 'blocked' ? AuditLevel.SECURITY : AuditLevel.INFO,
      tool,
      action: 'tool_call',
      target: target ? this.maskTarget(target) : undefined,
      result,
      details,
      error,
      duration
    });
  }

  logSecurityEvent(
    tool: string,
    action: string,
    details: Record<string, unknown>
  ): void {
    this.log({
      level: AuditLevel.SECURITY,
      tool,
      action,
      result: 'blocked',
      details
    });
  }

  logScopeViolation(tool: string, target: string): void {
    this.log({
      level: AuditLevel.SECURITY,
      tool,
      action: 'scope_violation',
      target: this.maskTarget(target),
      result: 'blocked',
      details: { reason: 'Target not in authorized scope' }
    });
  }

  logRateLimitExceeded(tool: string, domain: string): void {
    this.log({
      level: AuditLevel.WARN,
      tool,
      action: 'rate_limit_exceeded',
      target: domain,
      result: 'blocked',
      details: { reason: 'Rate limit exceeded' }
    });
  }

  logCommandExecution(
    command: string,
    args: string[],
    exitCode: number | null,
    duration: number
  ): void {
    this.log({
      level: AuditLevel.INFO,
      tool: 'executor',
      action: 'command_execution',
      result: exitCode === 0 ? 'success' : 'failure',
      details: {
        command: this.maskCommand(command),
        argCount: args.length,
        exitCode
      },
      duration
    });
  }

  getEntries(filter?: {
    level?: AuditLevel;
    tool?: string;
    result?: string;
    since?: Date;
  }): AuditEntry[] {
    let filtered = [...this.entries];

    if (filter?.level) {
      filtered = filtered.filter(e => e.level === filter.level);
    }
    if (filter?.tool) {
      filtered = filtered.filter(e => e.tool === filter.tool);
    }
    if (filter?.result) {
      filtered = filtered.filter(e => e.result === filter.result);
    }
    if (filter?.since) {
      const sinceTime = filter.since.getTime();
      filtered = filtered.filter(e => new Date(e.timestamp).getTime() >= sinceTime);
    }

    return filtered;
  }

  getSecurityEvents(): AuditEntry[] {
    return this.getEntries({ level: AuditLevel.SECURITY });
  }

  getRecentActivity(limit: number = 50): AuditEntry[] {
    return this.entries.slice(-limit);
  }

  clear(): void {
    this.entries = [];
  }

  getStats(): {
    total: number;
    byLevel: Record<string, number>;
    byResult: Record<string, number>;
    byTool: Record<string, number>;
  } {
    const stats = {
      total: this.entries.length,
      byLevel: {} as Record<string, number>,
      byResult: {} as Record<string, number>,
      byTool: {} as Record<string, number>
    };

    for (const entry of this.entries) {
      stats.byLevel[entry.level] = (stats.byLevel[entry.level] || 0) + 1;
      stats.byResult[entry.result] = (stats.byResult[entry.result] || 0) + 1;
      stats.byTool[entry.tool] = (stats.byTool[entry.tool] || 0) + 1;
    }

    return stats;
  }

  exportLog(): string {
    return this.entries.map(e =>
      `[${e.timestamp}] [${e.level}] ${e.tool}: ${e.action} - ${e.result}` +
      (e.target ? ` (target: ${e.target})` : '') +
      (e.error ? ` - Error: ${e.error}` : '')
    ).join('\n');
  }

  private maskTarget(target: string): string {
    if (target.length <= 10) return target;

    try {
      const url = new URL(target);
      return `${url.protocol}//${url.hostname}/...`;
    } catch {
      if (target.length > 30) {
        return target.slice(0, 15) + '...' + target.slice(-10);
      }
      return target;
    }
  }

  private maskCommand(command: string): string {
    const parts = command.split(/\s+/);
    return parts[0];
  }

  private logToConsole(entry: AuditEntry): void {
    const prefix = entry.level === AuditLevel.SECURITY ? '🔒 SECURITY' : '❌ ERROR';
    console.error(`${prefix}: [${entry.tool}] ${entry.action} - ${entry.result}`);
  }
}

export const auditLogger = new AuditLogger();

export function withAudit<T>(
  tool: string,
  target: string | undefined,
  fn: () => Promise<T>
): Promise<T> {
  const startTime = Date.now();

  return fn()
    .then(result => {
      auditLogger.logToolCall(tool, target, 'success', undefined, undefined, Date.now() - startTime);
      return result;
    })
    .catch(error => {
      auditLogger.logToolCall(
        tool,
        target,
        'failure',
        undefined,
        error instanceof Error ? error.message : 'Unknown error',
        Date.now() - startTime
      );
      throw error;
    });
}
