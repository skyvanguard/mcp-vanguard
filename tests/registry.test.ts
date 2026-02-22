import { describe, it, expect, beforeEach } from 'vitest';
import { z } from 'zod';
import { ToolRegistry } from '../src/registry.js';
import { PermissionTier } from '../src/config.js';
import { ToolDefinition } from '../src/types/tool.js';

function makeTool(overrides: Partial<ToolDefinition> = {}): ToolDefinition {
  return {
    name: 'test_tool',
    description: 'A test tool',
    category: 'test',
    permission: PermissionTier.SAFE,
    schema: z.object({ input: z.string() }),
    handler: async (args: { input: string }) => ({ result: args.input }),
    executionMode: 'native',
    ...overrides
  };
}

describe('ToolRegistry', () => {
  let reg: ToolRegistry;

  beforeEach(() => {
    reg = new ToolRegistry();
  });

  describe('register', () => {
    it('should register a tool', () => {
      reg.register(makeTool());
      expect(reg.size()).toBe(1);
    });

    it('should throw on duplicate registration', () => {
      reg.register(makeTool());
      expect(() => reg.register(makeTool())).toThrow('already registered');
    });
  });

  describe('registerAll', () => {
    it('should register multiple tools', () => {
      reg.registerAll([
        makeTool({ name: 'tool_a' }),
        makeTool({ name: 'tool_b' }),
        makeTool({ name: 'tool_c' })
      ]);
      expect(reg.size()).toBe(3);
    });
  });

  describe('get', () => {
    it('should return registered tool', () => {
      reg.register(makeTool({ name: 'my_tool' }));
      const tool = reg.get('my_tool');
      expect(tool).toBeDefined();
      expect(tool!.name).toBe('my_tool');
    });

    it('should return undefined for unknown tool', () => {
      expect(reg.get('nonexistent')).toBeUndefined();
    });
  });

  describe('getAll', () => {
    it('should return all registered tools', () => {
      reg.registerAll([
        makeTool({ name: 'tool_a' }),
        makeTool({ name: 'tool_b' })
      ]);
      expect(reg.getAll()).toHaveLength(2);
    });
  });

  describe('getByCategory', () => {
    it('should filter by category', () => {
      reg.registerAll([
        makeTool({ name: 'recon_a', category: 'recon' }),
        makeTool({ name: 'web_a', category: 'web' }),
        makeTool({ name: 'recon_b', category: 'recon' })
      ]);
      expect(reg.getByCategory('recon')).toHaveLength(2);
      expect(reg.getByCategory('web')).toHaveLength(1);
      expect(reg.getByCategory('osint')).toHaveLength(0);
    });
  });

  describe('getPermission', () => {
    it('should return tool permission', () => {
      reg.register(makeTool({ name: 'safe_tool', permission: PermissionTier.SAFE }));
      reg.register(makeTool({ name: 'dangerous_tool', permission: PermissionTier.DANGEROUS }));
      expect(reg.getPermission('safe_tool')).toBe(PermissionTier.SAFE);
      expect(reg.getPermission('dangerous_tool')).toBe(PermissionTier.DANGEROUS);
    });

    it('should return BLOCKED for unknown tools', () => {
      expect(reg.getPermission('unknown')).toBe(PermissionTier.BLOCKED);
    });
  });

  describe('getCategories', () => {
    it('should return unique categories', () => {
      reg.registerAll([
        makeTool({ name: 'a', category: 'recon' }),
        makeTool({ name: 'b', category: 'web' }),
        makeTool({ name: 'c', category: 'recon' })
      ]);
      const cats = reg.getCategories();
      expect(cats).toHaveLength(2);
      expect(cats).toContain('recon');
      expect(cats).toContain('web');
    });
  });

  describe('getRequiredWSLCommands', () => {
    it('should collect WSL commands from tools', () => {
      reg.registerAll([
        makeTool({ name: 'a', wslCommands: ['nmap', 'dig'] }),
        makeTool({ name: 'b', wslCommands: ['nmap', 'curl'] }),
        makeTool({ name: 'c' })
      ]);
      const cmds = reg.getRequiredWSLCommands();
      expect(cmds).toContain('nmap');
      expect(cmds).toContain('dig');
      expect(cmds).toContain('curl');
      expect(cmds).toHaveLength(3);
    });
  });

  describe('getRequiredWindowsCommands', () => {
    it('should collect Windows commands from tools', () => {
      reg.registerAll([
        makeTool({ name: 'a', windowsCommands: ['nmap'] }),
        makeTool({ name: 'b', windowsCommands: ['ffuf'] })
      ]);
      const cmds = reg.getRequiredWindowsCommands();
      expect(cmds).toContain('nmap');
      expect(cmds).toContain('ffuf');
      expect(cmds).toHaveLength(2);
    });
  });

  describe('toMCPTools', () => {
    it('should convert to MCP format', () => {
      reg.register(makeTool({ name: 'mcp_test', description: 'MCP test tool' }));
      const mcpTools = reg.toMCPTools();
      expect(mcpTools).toHaveLength(1);
      expect(mcpTools[0].name).toBe('mcp_test');
      expect(mcpTools[0].description).toBe('MCP test tool');
      expect(mcpTools[0].inputSchema).toBeDefined();
      expect(mcpTools[0].inputSchema.type).toBe('object');
    });
  });
});
