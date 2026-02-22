import { z } from 'zod';
import { PermissionTier } from '../config.js';

export type ExecutionMode = 'native' | 'api' | 'wsl' | 'hybrid';

export interface ToolDefinition {
  name: string;
  description: string;
  category: string;
  permission: PermissionTier;
  schema: z.ZodObject<z.ZodRawShape>;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  handler: (args: any) => any;
  executionMode: ExecutionMode;
  wslCommands?: string[];
  windowsCommands?: string[];
  requiresScope?: boolean;
  tags?: string[];
}
