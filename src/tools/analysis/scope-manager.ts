import { z } from 'zod';
import { setScope, getScope, isInScope } from '../../config.js';

export const scopeManagerSchema = z.object({
  action: z.enum(['set', 'add', 'remove', 'list', 'check']).describe('Scope management action'),
  targets: z.array(z.string()).optional().describe('Targets to set/add/remove'),
  check: z.string().optional().describe('Target to check if in scope'),
});

export type ScopeManagerInput = z.infer<typeof scopeManagerSchema>;

export async function scopeManager(input: ScopeManagerInput): Promise<{
  success: boolean;
  action: string;
  scope: string[];
  result?: string;
  inScope?: boolean;
}> {
  const { action, targets, check } = input;
  let currentScope = getScope();

  switch (action) {
    case 'set':
      setScope(targets || []);
      return { success: true, action, scope: targets || [], result: `Scope set to ${(targets || []).length} targets` };

    case 'add':
      if (targets) {
        const newScope = [...new Set([...currentScope, ...targets])];
        setScope(newScope);
        return { success: true, action, scope: newScope, result: `Added ${targets.length} targets` };
      }
      return { success: false, action, scope: currentScope, result: 'No targets provided' };

    case 'remove':
      if (targets) {
        const filtered = currentScope.filter(s => !targets.includes(s));
        setScope(filtered);
        return { success: true, action, scope: filtered, result: `Removed ${currentScope.length - filtered.length} targets` };
      }
      return { success: false, action, scope: currentScope, result: 'No targets provided' };

    case 'list':
      return { success: true, action, scope: currentScope, result: `${currentScope.length} targets in scope` };

    case 'check':
      if (check) {
        const inScope = isInScope(check);
        return { success: true, action, scope: currentScope, result: `${check} is ${inScope ? 'IN' : 'OUT OF'} scope`, inScope };
      }
      return { success: false, action, scope: currentScope, result: 'No target to check' };

    default:
      return { success: false, action, scope: currentScope, result: 'Unknown action' };
  }
}
