import { z } from 'zod';
import { setScope, getScope, isInScope } from '../../config.js';

export const setScopeSchema = z.object({
  targets: z.array(z.string()).describe('List of in-scope targets (domains, IPs, CIDR ranges)'),
  append: z.boolean().default(false).describe('Append to existing scope instead of replacing')
});

export type SetScopeInput = z.infer<typeof setScopeSchema>;

export const checkScopeSchema = z.object({
  target: z.string().describe('Target to check against scope')
});

export type CheckScopeInput = z.infer<typeof checkScopeSchema>;

export function setScopeTargets(input: SetScopeInput): {
  success: boolean;
  scope: string[];
  message: string;
} {
  const { targets, append } = input;

  const normalizedTargets = targets.map(t => t.toLowerCase().trim());

  if (append) {
    const currentScope = getScope();
    const newScope = Array.from(new Set([...currentScope, ...normalizedTargets]));
    setScope(newScope);

    return {
      success: true,
      scope: newScope,
      message: `Added ${normalizedTargets.length} targets to scope. Total: ${newScope.length} targets.`
    };
  } else {
    setScope(normalizedTargets);

    return {
      success: true,
      scope: normalizedTargets,
      message: `Scope set to ${normalizedTargets.length} targets.`
    };
  }
}

export function checkScopeTarget(input: CheckScopeInput): {
  target: string;
  inScope: boolean;
  matchedRule?: string;
  scope: string[];
} {
  const { target } = input;
  const scope = getScope();

  if (scope.length === 0) {
    return {
      target,
      inScope: true,
      matchedRule: '(no scope defined - all targets allowed)',
      scope
    };
  }

  const normalizedTarget = target.toLowerCase();

  for (const scopeItem of scope) {
    const normalizedScope = scopeItem.toLowerCase();

    if (normalizedScope.startsWith('*.')) {
      const domain = normalizedScope.slice(2);
      if (normalizedTarget === domain || normalizedTarget.endsWith('.' + domain)) {
        return {
          target,
          inScope: true,
          matchedRule: scopeItem,
          scope
        };
      }
    }

    if (normalizedScope.includes('/')) {
      if (normalizedTarget.startsWith(normalizedScope) ||
          normalizedTarget.includes(normalizedScope)) {
        return {
          target,
          inScope: true,
          matchedRule: scopeItem,
          scope
        };
      }
    }

    if (normalizedTarget === normalizedScope ||
        normalizedTarget.endsWith('.' + normalizedScope)) {
      return {
        target,
        inScope: true,
        matchedRule: scopeItem,
        scope
      };
    }
  }

  return {
    target,
    inScope: false,
    scope
  };
}

export function clearScope(): {
  success: boolean;
  message: string;
} {
  setScope([]);
  return {
    success: true,
    message: 'Scope cleared. All targets are now allowed (use with caution).'
  };
}

export function removeFromScope(targets: string[]): {
  success: boolean;
  removed: string[];
  scope: string[];
  message: string;
} {
  const currentScope = getScope();
  const normalizedTargets = targets.map(t => t.toLowerCase().trim());

  const removed: string[] = [];
  const newScope = currentScope.filter(item => {
    const shouldRemove = normalizedTargets.includes(item.toLowerCase());
    if (shouldRemove) {
      removed.push(item);
    }
    return !shouldRemove;
  });

  setScope(newScope);

  return {
    success: true,
    removed,
    scope: newScope,
    message: `Removed ${removed.length} targets from scope. Remaining: ${newScope.length} targets.`
  };
}

export function validateScopeEntry(entry: string): {
  valid: boolean;
  type: 'domain' | 'wildcard' | 'ip' | 'cidr' | 'unknown';
  normalized: string;
  warnings: string[];
} {
  const warnings: string[] = [];
  const normalized = entry.toLowerCase().trim();

  const ipRegex = /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/;
  if (ipRegex.test(normalized)) {
    const parts = normalized.split('.').map(Number);
    if (parts.every(p => p >= 0 && p <= 255)) {
      return { valid: true, type: 'ip', normalized, warnings };
    }
    return {
      valid: false,
      type: 'ip',
      normalized,
      warnings: ['Invalid IP address']
    };
  }

  const cidrRegex = /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\/\d{1,2}$/;
  if (cidrRegex.test(normalized)) {
    const [ip, mask] = normalized.split('/');
    const maskNum = parseInt(mask, 10);
    if (maskNum >= 0 && maskNum <= 32) {
      if (maskNum < 16) {
        warnings.push('Large CIDR range - this includes many IP addresses');
      }
      return { valid: true, type: 'cidr', normalized, warnings };
    }
    return {
      valid: false,
      type: 'cidr',
      normalized,
      warnings: ['Invalid CIDR mask']
    };
  }

  if (normalized.startsWith('*.')) {
    const domain = normalized.slice(2);
    if (isValidDomain(domain)) {
      return { valid: true, type: 'wildcard', normalized, warnings };
    }
    return {
      valid: false,
      type: 'wildcard',
      normalized,
      warnings: ['Invalid wildcard domain']
    };
  }

  if (isValidDomain(normalized)) {
    return { valid: true, type: 'domain', normalized, warnings };
  }

  return {
    valid: false,
    type: 'unknown',
    normalized,
    warnings: ['Unrecognized scope entry format']
  };
}

function isValidDomain(domain: string): boolean {
  if (domain.length > 253) return false;

  const domainRegex = /^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*$/;
  return domainRegex.test(domain);
}
