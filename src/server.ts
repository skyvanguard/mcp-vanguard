import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import {
  CallToolRequestSchema,
  ListToolsRequestSchema
} from '@modelcontextprotocol/sdk/types.js';

import { PermissionTier } from './config.js';
import { registry } from './registry.js';
import { auditLogger } from './utils/audit.js';
import { toSafeError, formatSafeError, ToolError } from './utils/safe-error.js';

import { reconTools } from './tools/recon/index.js';
import { webTools } from './tools/web/index.js';
import { osintTools } from './tools/osint/index.js';
import { utilsTools } from './tools/utils/index.js';
import { networkTools } from './tools/network/index.js';
import { exploitTools } from './tools/exploit/index.js';
import { cryptoTools } from './tools/crypto/index.js';
import { cloudTools } from './tools/cloud/index.js';

// Register all tools
registry.registerAll([
  ...reconTools,
  ...webTools,
  ...osintTools,
  ...utilsTools,
  ...networkTools,
  ...exploitTools,
  ...cryptoTools,
  ...cloudTools
]);

export async function createServer(): Promise<Server> {
  const server = new Server(
    {
      name: 'mcp-vanguard',
      version: '2.5.0'
    },
    {
      capabilities: {
        tools: {}
      }
    }
  );

  server.setRequestHandler(ListToolsRequestSchema, async () => {
    return { tools: registry.toMCPTools() };
  });

  server.setRequestHandler(CallToolRequestSchema, async (request) => {
    const { name, arguments: args } = request.params;
    const startTime = Date.now();

    const permission = registry.getPermission(name);
    if (permission === PermissionTier.BLOCKED) {
      auditLogger.logSecurityEvent(name, 'tool_blocked', { permission: 'BLOCKED' });
      return {
        content: [{
          type: 'text',
          text: formatSafeError(new ToolError('TOOL_BLOCKED', name).toSafeError())
        }],
        isError: true
      };
    }

    const tool = registry.get(name);
    if (!tool) {
      auditLogger.logToolCall(name, undefined, 'failure', undefined, 'Unknown tool');
      return {
        content: [{
          type: 'text',
          text: formatSafeError(new ToolError('INVALID_INPUT', name, 'Unknown tool').toSafeError())
        }],
        isError: true
      };
    }

    try {
      const parsed = tool.schema.parse(args);
      const result = await tool.handler(parsed);

      const duration = Date.now() - startTime;
      auditLogger.logToolCall(name, undefined, 'success', undefined, undefined, duration);

      return {
        content: [{
          type: 'text',
          text: JSON.stringify(result, null, 2)
        }]
      };
    } catch (error) {
      const duration = Date.now() - startTime;
      const safeError = toSafeError(error, name);

      auditLogger.logToolCall(
        name,
        undefined,
        'failure',
        undefined,
        safeError.message,
        duration
      );

      return {
        content: [{
          type: 'text',
          text: formatSafeError(safeError)
        }],
        isError: true
      };
    }
  });

  return server;
}

export async function runServer(): Promise<void> {
  const server = await createServer();
  const transport = new StdioServerTransport();
  await server.connect(transport);
}
