import { z } from 'zod';
import { isInScope, getConfig } from '../../config.js';
import { executeWSL, checkWSLCommandExists } from '../../executor/wsl.js';

export const ldapEnumSchema = z.object({
  target: z.string().describe('Target LDAP server IP or hostname'),
  port: z.number().default(389).describe('LDAP port (389 or 636 for LDAPS)'),
  baseDn: z.string().default('').describe('Base DN for search (auto-detected if empty)'),
  anonymous: z.boolean().default(true).describe('Use anonymous bind'),
  timeout: z.number().default(60000).describe('Timeout in milliseconds')
});

export type LdapEnumInput = z.infer<typeof ldapEnumSchema>;

interface LdapEntry {
  dn: string;
  attributes: Record<string, string[]>;
}

export async function ldapEnum(input: LdapEnumInput): Promise<{
  success: boolean;
  target: string;
  baseDn: string;
  entries: LdapEntry[];
  namingContexts?: string[];
  error?: string;
}> {
  const { target, port, baseDn, anonymous, timeout } = input;

  if (!isInScope(target)) {
    return {
      success: false,
      target,
      baseDn,
      entries: [],
      error: `Target ${target} is not in scope. Use vanguard_set_scope first.`
    };
  }

  const config = getConfig();
  if (!config.wslEnabled) {
    return { success: false, target, baseDn, entries: [], error: 'WSL required for LDAP enumeration' };
  }

  const ldapAvailable = await checkWSLCommandExists('ldapsearch');
  if (!ldapAvailable) {
    return { success: false, target, baseDn, entries: [], error: 'ldapsearch not found in WSL. Install: apt install ldap-utils' };
  }

  // If no baseDn, try to get naming contexts
  let effectiveBaseDn = baseDn;
  let namingContexts: string[] | undefined;

  if (!effectiveBaseDn) {
    const rootResult = await executeWSL('ldapsearch', [
      '-x', '-H', `ldap://${target}:${port}`, '-s', 'base', '-b', '',
      'namingContexts'
    ], { timeout });

    if (rootResult.stdout) {
      namingContexts = extractValues(rootResult.stdout, 'namingContexts');
      if (namingContexts.length > 0) {
        effectiveBaseDn = namingContexts[0];
      }
    }
  }

  if (!effectiveBaseDn) {
    return {
      success: false,
      target,
      baseDn: '',
      entries: [],
      namingContexts,
      error: 'Could not determine base DN. Provide baseDn parameter.'
    };
  }

  const args = [
    '-x', '-H', `ldap://${target}:${port}`,
    '-b', effectiveBaseDn,
    '-s', 'sub',
    '(objectClass=*)'
  ];

  if (anonymous) {
    // Anonymous bind (already -x)
  }

  const result = await executeWSL('ldapsearch', args, { timeout });

  if (!result.success && !result.stdout) {
    return { success: false, target, baseDn: effectiveBaseDn, entries: [], error: result.stderr || 'LDAP search failed' };
  }

  return {
    success: true,
    target,
    baseDn: effectiveBaseDn,
    entries: parseLdifOutput(result.stdout),
    namingContexts
  };
}

function extractValues(ldif: string, attribute: string): string[] {
  const values: string[] = [];
  const pattern = new RegExp(`^${attribute}:\\s*(.+)$`, 'gm');
  let match;
  while ((match = pattern.exec(ldif)) !== null) {
    values.push(match[1].trim());
  }
  return values;
}

function parseLdifOutput(output: string): LdapEntry[] {
  const entries: LdapEntry[] = [];
  const blocks = output.split(/\n\n+/);

  for (const block of blocks) {
    const lines = block.split('\n');
    let dn = '';
    const attributes: Record<string, string[]> = {};

    for (const line of lines) {
      if (line.startsWith('#') || line.trim() === '') continue;

      const match = line.match(/^(\w[\w;-]*):\s*(.*)$/);
      if (match) {
        const [, attr, value] = match;
        if (attr === 'dn') {
          dn = value;
        } else {
          if (!attributes[attr]) attributes[attr] = [];
          attributes[attr].push(value);
        }
      }
    }

    if (dn) {
      entries.push({ dn, attributes });
    }
  }

  return entries;
}
