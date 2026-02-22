import { PermissionTier } from '../../config.js';
import { ToolDefinition } from '../../types/tool.js';
import { setScopeSchema, setScopeTargets, checkScopeSchema, checkScopeTarget } from './scope.js';
import { generateReportSchema, generateReport } from './report.js';
import { exportHtmlSchema, exportHtml } from './export-html.js';
import { auditStatsSchema, auditStats } from './audit-stats.js';

export const utilsTools: ToolDefinition[] = [
  {
    name: 'vanguard_set_scope',
    description: 'Define authorized targets (domains, IPs, CIDR). SAFE.',
    category: 'utils',
    permission: PermissionTier.SAFE,
    schema: setScopeSchema,
    handler: setScopeTargets,
    executionMode: 'native',
    tags: ['scope', 'targets', 'config']
  },
  {
    name: 'vanguard_check_scope',
    description: 'Verify if target is within defined scope. SAFE.',
    category: 'utils',
    permission: PermissionTier.SAFE,
    schema: checkScopeSchema,
    handler: checkScopeTarget,
    executionMode: 'native',
    tags: ['scope', 'verify']
  },
  {
    name: 'vanguard_generate_report',
    description: 'Generate markdown security report from findings. SAFE.',
    category: 'utils',
    permission: PermissionTier.SAFE,
    schema: generateReportSchema,
    handler: generateReport,
    executionMode: 'native',
    tags: ['report', 'markdown']
  },
  {
    name: 'vanguard_export_html',
    description: 'Convert markdown report to styled HTML. SAFE.',
    category: 'utils',
    permission: PermissionTier.SAFE,
    schema: exportHtmlSchema,
    handler: exportHtml,
    executionMode: 'native',
    tags: ['report', 'html', 'export']
  },
  {
    name: 'vanguard_audit_stats',
    description: 'View audit log statistics and security events. SAFE: Internal monitoring.',
    category: 'utils',
    permission: PermissionTier.SAFE,
    schema: auditStatsSchema,
    handler: auditStats,
    executionMode: 'native',
    tags: ['audit', 'stats', 'monitoring']
  }
];
