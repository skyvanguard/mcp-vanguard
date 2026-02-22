import { z } from 'zod';

export const remediationPlanSchema = z.object({
  findings: z.array(z.object({
    type: z.string(),
    severity: z.enum(['info', 'low', 'medium', 'high', 'critical']),
    target: z.string(),
    details: z.string(),
  })).describe('Security findings to generate remediation for'),
});

export type RemediationPlanInput = z.infer<typeof remediationPlanSchema>;

interface RemediationItem {
  finding: string;
  severity: string;
  priority: number;
  remediation: string;
  effort: 'low' | 'medium' | 'high';
  category: string;
}

const REMEDIATION_MAP: Record<string, { remediation: string; effort: 'low' | 'medium' | 'high'; category: string }> = {
  sqli: { remediation: 'Use parameterized queries/prepared statements. Implement input validation. Enable WAF SQL injection rules.', effort: 'medium', category: 'Input Validation' },
  xss: { remediation: 'Implement output encoding (HTML, JS, URL context-aware). Deploy Content-Security-Policy header. Use framework auto-escaping.', effort: 'medium', category: 'Input Validation' },
  ssrf: { remediation: 'Whitelist allowed URLs/IPs. Block private IP ranges. Use a proxy for outbound requests. Disable unnecessary URL schemes.', effort: 'medium', category: 'Input Validation' },
  lfi: { remediation: 'Whitelist allowed file paths. Remove path traversal sequences. Use chroot/jail for file access. Disable PHP wrappers.', effort: 'medium', category: 'Input Validation' },
  command: { remediation: 'Avoid OS commands. Use language-native libraries instead. If unavoidable, whitelist allowed characters/commands.', effort: 'high', category: 'Input Validation' },
  redirect: { remediation: 'Whitelist allowed redirect URLs. Use relative paths only. Validate redirect destination server-side.', effort: 'low', category: 'Input Validation' },
  crlf: { remediation: 'Strip CR/LF characters from user input before use in HTTP headers. Use framework header methods.', effort: 'low', category: 'Input Validation' },
  deserialization: { remediation: 'Avoid deserializing untrusted data. Use JSON instead of native serialization. Implement type whitelisting.', effort: 'high', category: 'Data Handling' },
  hsts: { remediation: 'Add Strict-Transport-Security header with max-age >= 31536000 and includeSubDomains.', effort: 'low', category: 'Headers' },
  csp: { remediation: 'Implement Content-Security-Policy header. Start with report-only mode, then enforce.', effort: 'medium', category: 'Headers' },
  jwt: { remediation: 'Use strong secrets (>= 256 bits). Set short expiration. Validate algorithm server-side. Never use "none".', effort: 'medium', category: 'Authentication' },
  password: { remediation: 'Enforce strong password policy (12+ chars, complexity). Use bcrypt/Argon2 for hashing. Implement rate limiting.', effort: 'low', category: 'Authentication' },
  s3: { remediation: 'Enable S3 Block Public Access. Review bucket policies. Enable access logging. Use presigned URLs.', effort: 'low', category: 'Cloud' },
  docker: { remediation: 'Never expose Docker socket. Use rootless containers. Drop all capabilities. Set readOnlyRootFilesystem.', effort: 'medium', category: 'Container' },
  takeover: { remediation: 'Remove dangling DNS records. Claim or delete unused cloud resources. Monitor CNAME records.', effort: 'low', category: 'DNS' },
  env: { remediation: 'Remove exposed files from webroot. Block access via web server config. Use .gitignore.', effort: 'low', category: 'Configuration' },
};

export async function remediationPlan(input: RemediationPlanInput): Promise<{
  success: boolean;
  plan: RemediationItem[];
  summary: { immediate: number; shortTerm: number; longTerm: number };
  estimatedEffort: string;
}> {
  const { findings } = input;
  const plan: RemediationItem[] = [];

  const priorityOrder: Record<string, number> = { critical: 1, high: 2, medium: 3, low: 4, info: 5 };

  for (const f of findings) {
    const type = f.type.toLowerCase();
    let matched = false;

    for (const [key, rem] of Object.entries(REMEDIATION_MAP)) {
      if (type.includes(key)) {
        plan.push({
          finding: `${f.type} on ${f.target}`,
          severity: f.severity,
          priority: priorityOrder[f.severity] || 5,
          remediation: rem.remediation,
          effort: rem.effort,
          category: rem.category,
        });
        matched = true;
        break;
      }
    }

    if (!matched) {
      plan.push({
        finding: `${f.type} on ${f.target}`,
        severity: f.severity,
        priority: priorityOrder[f.severity] || 5,
        remediation: `Review and remediate ${f.type} vulnerability. Consult OWASP guidelines for specific mitigation.`,
        effort: 'medium',
        category: 'General',
      });
    }
  }

  // Sort by priority
  plan.sort((a, b) => a.priority - b.priority);

  const immediate = plan.filter(p => p.priority <= 2).length;
  const shortTerm = plan.filter(p => p.priority === 3).length;
  const longTerm = plan.filter(p => p.priority >= 4).length;

  const highEffort = plan.filter(p => p.effort === 'high').length;
  const medEffort = plan.filter(p => p.effort === 'medium').length;
  const lowEffort = plan.filter(p => p.effort === 'low').length;
  const estimatedEffort = `${lowEffort} low-effort, ${medEffort} medium-effort, ${highEffort} high-effort items`;

  return {
    success: true,
    plan,
    summary: { immediate, shortTerm, longTerm },
    estimatedEffort,
  };
}
