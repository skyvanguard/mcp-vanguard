/**
 * Audit statistics and security monitoring tool
 */

import { z } from 'zod';
import { auditLogger, AuditLevel } from '../../utils/audit.js';

export const auditStatsSchema = z.object({
  action: z.enum(['stats', 'security_events', 'recent', 'export'])
    .describe('Action to perform: stats (get statistics), security_events (list blocked actions), recent (recent activity), export (full log)'),
  limit: z.number().default(50).describe('Maximum entries to return for recent/security_events')
});

export function auditStats(params: z.infer<typeof auditStatsSchema>): {
  action: string;
  data: unknown;
} {
  const { action, limit } = params;

  switch (action) {
    case 'stats':
      return {
        action: 'stats',
        data: auditLogger.getStats()
      };

    case 'security_events':
      return {
        action: 'security_events',
        data: auditLogger.getSecurityEvents().slice(-limit)
      };

    case 'recent':
      return {
        action: 'recent',
        data: auditLogger.getRecentActivity(limit)
      };

    case 'export':
      return {
        action: 'export',
        data: {
          log: auditLogger.exportLog(),
          stats: auditLogger.getStats()
        }
      };

    default:
      return {
        action: 'error',
        data: { error: 'Unknown action' }
      };
  }
}
