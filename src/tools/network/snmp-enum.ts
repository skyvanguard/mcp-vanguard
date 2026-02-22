import { z } from 'zod';
import { isInScope, getConfig } from '../../config.js';
import { executeWSL, checkWSLCommandExists } from '../../executor/wsl.js';

export const snmpEnumSchema = z.object({
  target: z.string().describe('Target IP or hostname'),
  community: z.string().default('public').describe('SNMP community string'),
  version: z.enum(['1', '2c']).default('2c').describe('SNMP version'),
  oid: z.string().default('1.3.6.1.2.1').describe('OID to walk (default: system MIB)'),
  timeout: z.number().default(60000).describe('Timeout in milliseconds')
});

export type SnmpEnumInput = z.infer<typeof snmpEnumSchema>;

interface SnmpEntry {
  oid: string;
  type: string;
  value: string;
}

export async function snmpEnum(input: SnmpEnumInput): Promise<{
  success: boolean;
  target: string;
  entries: SnmpEntry[];
  error?: string;
}> {
  const { target, community, version, oid, timeout } = input;

  if (!isInScope(target)) {
    return {
      success: false,
      target,
      entries: [],
      error: `Target ${target} is not in scope. Use vanguard_set_scope first.`
    };
  }

  const config = getConfig();
  if (!config.wslEnabled) {
    return { success: false, target, entries: [], error: 'WSL is required for SNMP enumeration' };
  }

  const snmpAvailable = await checkWSLCommandExists('snmpwalk');
  if (!snmpAvailable) {
    return { success: false, target, entries: [], error: 'snmpwalk not found in WSL. Install: apt install snmp' };
  }

  const args = [`-v${version}`, '-c', community, target, oid];
  const result = await executeWSL('snmpwalk', args, { timeout });

  if (!result.success && !result.stdout) {
    return { success: false, target, entries: [], error: result.stderr || 'SNMP walk failed' };
  }

  return {
    success: true,
    target,
    entries: parseSnmpOutput(result.stdout)
  };
}

function parseSnmpOutput(output: string): SnmpEntry[] {
  const entries: SnmpEntry[] = [];
  const lines = output.split('\n');

  for (const line of lines) {
    const match = line.match(/^(\S+)\s*=\s*(\w+):\s*(.+)$/);
    if (match) {
      entries.push({
        oid: match[1],
        type: match[2],
        value: match[3].trim()
      });
    }
  }

  return entries;
}
