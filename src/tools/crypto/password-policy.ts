import { z } from 'zod';

export const passwordPolicySchema = z.object({
  password: z.string().describe('Password to analyze'),
});

export type PasswordPolicyInput = z.infer<typeof passwordPolicySchema>;

interface PolicyCheck {
  rule: string;
  passed: boolean;
  details: string;
}

export async function passwordPolicy(input: PasswordPolicyInput): Promise<{
  success: boolean;
  password: string;
  length: number;
  score: number;
  strength: 'very_weak' | 'weak' | 'fair' | 'strong' | 'very_strong';
  checks: PolicyCheck[];
  entropy: number;
  crackTimeEstimate: string;
}> {
  const { password } = input;
  const checks: PolicyCheck[] = [];
  let score = 0;

  // Length checks
  checks.push({
    rule: 'Minimum 8 characters',
    passed: password.length >= 8,
    details: `Length: ${password.length}`,
  });
  if (password.length >= 8) score += 1;
  if (password.length >= 12) score += 1;
  if (password.length >= 16) score += 1;

  // Character class checks
  const hasLower = /[a-z]/.test(password);
  const hasUpper = /[A-Z]/.test(password);
  const hasDigit = /\d/.test(password);
  const hasSpecial = /[^a-zA-Z0-9]/.test(password);

  checks.push({ rule: 'Lowercase letters', passed: hasLower, details: hasLower ? 'Contains lowercase' : 'No lowercase' });
  checks.push({ rule: 'Uppercase letters', passed: hasUpper, details: hasUpper ? 'Contains uppercase' : 'No uppercase' });
  checks.push({ rule: 'Numbers', passed: hasDigit, details: hasDigit ? 'Contains digits' : 'No digits' });
  checks.push({ rule: 'Special characters', passed: hasSpecial, details: hasSpecial ? 'Contains special chars' : 'No special chars' });

  if (hasLower) score += 1;
  if (hasUpper) score += 1;
  if (hasDigit) score += 1;
  if (hasSpecial) score += 1;

  // Pattern checks
  const hasSequential = /(?:abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|mno|nop|opq|pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz|012|123|234|345|456|567|678|789)/i.test(password);
  const hasRepeated = /(.)\1{2,}/.test(password);
  const isCommon = ['password', '123456', 'qwerty', 'admin', 'letmein', 'welcome', 'monkey', 'dragon', 'master', 'login'].some(p => password.toLowerCase().includes(p));

  checks.push({ rule: 'No sequential patterns', passed: !hasSequential, details: hasSequential ? 'Contains sequential chars (abc, 123)' : 'No sequential patterns' });
  checks.push({ rule: 'No repeated characters (3+)', passed: !hasRepeated, details: hasRepeated ? 'Contains repeated chars' : 'No excessive repetition' });
  checks.push({ rule: 'Not a common password', passed: !isCommon, details: isCommon ? 'Contains common password pattern' : 'Not a common password' });

  if (hasSequential) score -= 1;
  if (hasRepeated) score -= 1;
  if (isCommon) score -= 2;

  // Entropy calculation
  let charsetSize = 0;
  if (hasLower) charsetSize += 26;
  if (hasUpper) charsetSize += 26;
  if (hasDigit) charsetSize += 10;
  if (hasSpecial) charsetSize += 33;
  if (charsetSize === 0) charsetSize = 1;

  const entropy = Math.round(password.length * Math.log2(charsetSize) * 100) / 100;

  // Crack time estimate (assuming 10B guesses/sec — modern GPU)
  const combinations = Math.pow(charsetSize, password.length);
  const seconds = combinations / 10_000_000_000;
  const crackTimeEstimate = formatTime(seconds);

  // Normalize score
  const normalizedScore = Math.max(0, Math.min(10, score));
  const strength = normalizedScore <= 2 ? 'very_weak'
    : normalizedScore <= 4 ? 'weak'
    : normalizedScore <= 6 ? 'fair'
    : normalizedScore <= 8 ? 'strong'
    : 'very_strong';

  return {
    success: true,
    password: password.slice(0, 2) + '*'.repeat(Math.max(0, password.length - 2)),
    length: password.length,
    score: normalizedScore,
    strength,
    checks,
    entropy,
    crackTimeEstimate,
  };
}

function formatTime(seconds: number): string {
  if (seconds < 1) return 'instant';
  if (seconds < 60) return `${Math.round(seconds)} seconds`;
  if (seconds < 3600) return `${Math.round(seconds / 60)} minutes`;
  if (seconds < 86400) return `${Math.round(seconds / 3600)} hours`;
  if (seconds < 86400 * 365) return `${Math.round(seconds / 86400)} days`;
  if (seconds < 86400 * 365 * 1000) return `${Math.round(seconds / (86400 * 365))} years`;
  if (seconds < 86400 * 365 * 1e6) return `${Math.round(seconds / (86400 * 365 * 1000))}K years`;
  if (seconds < 86400 * 365 * 1e9) return `${Math.round(seconds / (86400 * 365 * 1e6))}M years`;
  return 'centuries+';
}
