import { ToolDefinition } from '../../types/tool.js';
import { PermissionTier } from '../../config.js';

import { vulnCorrelateSchema, vulnCorrelate } from './vuln-correlate.js';
import { attackSurfaceSchema, attackSurface } from './attack-surface.js';
import { riskScoreSchema, riskScore } from './risk-score.js';
import { remediationPlanSchema, remediationPlan } from './remediation-plan.js';
import { encodingDetectSchema, encodingDetect } from './encoding-detect.js';
import { diffReportSchema, diffReport } from './diff-report.js';
import { timelineSchema, timeline } from './timeline.js';
import { scopeManagerSchema, scopeManager } from './scope-manager.js';
import { reportGenSchema, reportGen } from './report-gen.js';
export const analysisTools: ToolDefinition[] = [
  {
    name: 'vanguard_vuln_correlate',
    description: 'Correlate findings from multiple tools and detect attack chains',
    category: 'analysis',
    permission: PermissionTier.SAFE,
    schema: vulnCorrelateSchema,
    handler: vulnCorrelate,
    executionMode: 'native',
    tags: ['analysis', 'correlation', 'attack-chain'],
  },
  {
    name: 'vanguard_attack_surface',
    description: 'Map attack surface from ports, technologies, subdomains and services',
    category: 'analysis',
    permission: PermissionTier.SAFE,
    schema: attackSurfaceSchema,
    handler: attackSurface,
    executionMode: 'native',
    tags: ['analysis', 'attack-surface', 'mapping'],
  },
  {
    name: 'vanguard_risk_score',
    description: 'Calculate risk scores for findings with context multipliers',
    category: 'analysis',
    permission: PermissionTier.SAFE,
    schema: riskScoreSchema,
    handler: riskScore,
    executionMode: 'native',
    tags: ['analysis', 'risk', 'scoring'],
  },
  {
    name: 'vanguard_remediation_plan',
    description: 'Generate prioritized remediation plan from security findings',
    category: 'analysis',
    permission: PermissionTier.SAFE,
    schema: remediationPlanSchema,
    handler: remediationPlan,
    executionMode: 'native',
    tags: ['analysis', 'remediation', 'planning'],
  },
  {
    name: 'vanguard_encoding_detect',
    description: 'Detect and decode multi-layer encoding (Base64, URL, Hex, HTML entities)',
    category: 'analysis',
    permission: PermissionTier.SAFE,
    schema: encodingDetectSchema,
    handler: encodingDetect,
    executionMode: 'native',
    tags: ['analysis', 'encoding', 'decode'],
  },
  {
    name: 'vanguard_diff_report',
    description: 'Compare before/after scan results to track security posture changes',
    category: 'analysis',
    permission: PermissionTier.SAFE,
    schema: diffReportSchema,
    handler: diffReport,
    executionMode: 'native',
    tags: ['analysis', 'diff', 'comparison'],
  },
  {
    name: 'vanguard_timeline',
    description: 'Organize pentest events into chronological timeline with phase analysis',
    category: 'analysis',
    permission: PermissionTier.SAFE,
    schema: timelineSchema,
    handler: timeline,
    executionMode: 'native',
    tags: ['analysis', 'timeline', 'reporting'],
  },
  {
    name: 'vanguard_scope_manager',
    description: 'Manage target scope: set, add, remove, list, and check targets',
    category: 'analysis',
    permission: PermissionTier.SAFE,
    schema: scopeManagerSchema,
    handler: scopeManager,
    executionMode: 'native',
    tags: ['analysis', 'scope', 'management'],
  },
  {
    name: 'vanguard_report_gen',
    description: 'Generate security assessment reports in Markdown or JSON format',
    category: 'analysis',
    permission: PermissionTier.SAFE,
    schema: reportGenSchema,
    handler: reportGen,
    executionMode: 'native',
    tags: ['analysis', 'report', 'documentation'],
  },
];
