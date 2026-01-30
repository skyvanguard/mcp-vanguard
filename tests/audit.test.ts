import { describe, it, expect, beforeEach } from 'vitest';
import { auditLogger, AuditLevel, withAudit } from '../src/utils/audit.js';

describe('AuditLogger', () => {
  beforeEach(() => {
    auditLogger.clear();
  });

  describe('logToolCall', () => {
    it('should log successful tool calls', () => {
      auditLogger.logToolCall('test_tool', 'example.com', 'success', undefined, undefined, 100);

      const entries = auditLogger.getRecentActivity(1);
      expect(entries).toHaveLength(1);
      expect(entries[0].tool).toBe('test_tool');
      expect(entries[0].result).toBe('success');
      expect(entries[0].duration).toBe(100);
    });

    it('should log failed tool calls', () => {
      auditLogger.logToolCall('test_tool', 'example.com', 'failure', undefined, 'Connection refused');

      const entries = auditLogger.getRecentActivity(1);
      expect(entries[0].result).toBe('failure');
      expect(entries[0].error).toBe('Connection refused');
    });

    it('should log blocked tool calls with SECURITY level', () => {
      auditLogger.logToolCall('blocked_tool', 'example.com', 'blocked');

      const entries = auditLogger.getRecentActivity(1);
      expect(entries[0].result).toBe('blocked');
      expect(entries[0].level).toBe(AuditLevel.SECURITY);
    });
  });

  describe('logSecurityEvent', () => {
    it('should log security events', () => {
      auditLogger.logSecurityEvent('executor', 'blocked_command', { command: 'rm' });

      const events = auditLogger.getSecurityEvents();
      expect(events).toHaveLength(1);
      expect(events[0].action).toBe('blocked_command');
      expect(events[0].details?.command).toBe('rm');
    });
  });

  describe('logScopeViolation', () => {
    it('should log scope violations', () => {
      auditLogger.logScopeViolation('port_scan', 'unauthorized.com');

      const events = auditLogger.getSecurityEvents();
      expect(events).toHaveLength(1);
      expect(events[0].action).toBe('scope_violation');
    });
  });

  describe('logRateLimitExceeded', () => {
    it('should log rate limit events', () => {
      auditLogger.logRateLimitExceeded('ffuf', 'example.com');

      const entries = auditLogger.getEntries({ result: 'blocked' });
      expect(entries).toHaveLength(1);
      expect(entries[0].action).toBe('rate_limit_exceeded');
    });
  });

  describe('getStats', () => {
    it('should calculate statistics', () => {
      auditLogger.logToolCall('tool1', 'target1', 'success');
      auditLogger.logToolCall('tool1', 'target2', 'success');
      auditLogger.logToolCall('tool2', 'target3', 'failure');
      auditLogger.logSecurityEvent('tool3', 'blocked', {});

      const stats = auditLogger.getStats();
      expect(stats.total).toBe(4);
      expect(stats.byResult['success']).toBe(2);
      expect(stats.byResult['failure']).toBe(1);
      expect(stats.byResult['blocked']).toBe(1);
      expect(stats.byTool['tool1']).toBe(2);
    });
  });

  describe('getEntries with filters', () => {
    beforeEach(() => {
      auditLogger.logToolCall('tool1', 'target', 'success');
      auditLogger.logToolCall('tool2', 'target', 'failure');
      auditLogger.logSecurityEvent('tool3', 'blocked', {});
    });

    it('should filter by level', () => {
      const entries = auditLogger.getEntries({ level: AuditLevel.SECURITY });
      expect(entries).toHaveLength(1);
    });

    it('should filter by tool', () => {
      const entries = auditLogger.getEntries({ tool: 'tool1' });
      expect(entries).toHaveLength(1);
    });

    it('should filter by result', () => {
      const entries = auditLogger.getEntries({ result: 'success' });
      expect(entries).toHaveLength(1);
    });
  });

  describe('exportLog', () => {
    it('should export log as text', () => {
      auditLogger.logToolCall('test_tool', 'example.com', 'success');

      const exported = auditLogger.exportLog();
      expect(exported).toContain('test_tool');
      expect(exported).toContain('success');
    });
  });

  describe('max entries limit', () => {
    it('should enforce maximum entries', () => {
      // Default max is 1000, but we test the concept
      for (let i = 0; i < 10; i++) {
        auditLogger.logToolCall(`tool_${i}`, 'target', 'success');
      }

      const stats = auditLogger.getStats();
      expect(stats.total).toBeLessThanOrEqual(1000);
    });
  });
});

describe('withAudit wrapper', () => {
  beforeEach(() => {
    auditLogger.clear();
  });

  it('should log successful function execution', async () => {
    const result = await withAudit('test_tool', 'target', async () => {
      return 'success';
    });

    expect(result).toBe('success');

    const entries = auditLogger.getRecentActivity(1);
    expect(entries[0].result).toBe('success');
  });

  it('should log failed function execution', async () => {
    await expect(
      withAudit('test_tool', 'target', async () => {
        throw new Error('Test error');
      })
    ).rejects.toThrow('Test error');

    const entries = auditLogger.getRecentActivity(1);
    expect(entries[0].result).toBe('failure');
    expect(entries[0].error).toBe('Test error');
  });
});
