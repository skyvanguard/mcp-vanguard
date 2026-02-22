import { PermissionTier } from './config.js';
import { ToolDefinition } from './types/tool.js';
import { zodToJsonSchema } from './utils/zod-to-json.js';

export class ToolRegistry {
  private tools = new Map<string, ToolDefinition>();

  register(tool: ToolDefinition): void {
    if (this.tools.has(tool.name)) {
      throw new Error(`Tool "${tool.name}" is already registered`);
    }
    this.tools.set(tool.name, tool);
  }

  registerAll(tools: ToolDefinition[]): void {
    for (const tool of tools) {
      this.register(tool);
    }
  }

  get(name: string): ToolDefinition | undefined {
    return this.tools.get(name);
  }

  getAll(): ToolDefinition[] {
    return Array.from(this.tools.values());
  }

  getByCategory(category: string): ToolDefinition[] {
    return this.getAll().filter(t => t.category === category);
  }

  getPermission(name: string): PermissionTier {
    const tool = this.tools.get(name);
    return tool?.permission ?? PermissionTier.BLOCKED;
  }

  getCategories(): string[] {
    return [...new Set(this.getAll().map(t => t.category))];
  }

  getRequiredWSLCommands(): string[] {
    const cmds = new Set<string>();
    for (const tool of this.tools.values()) {
      if (tool.wslCommands) {
        for (const cmd of tool.wslCommands) {
          cmds.add(cmd);
        }
      }
    }
    return [...cmds];
  }

  getRequiredWindowsCommands(): string[] {
    const cmds = new Set<string>();
    for (const tool of this.tools.values()) {
      if (tool.windowsCommands) {
        for (const cmd of tool.windowsCommands) {
          cmds.add(cmd);
        }
      }
    }
    return [...cmds];
  }

  toMCPTools(): Array<{ name: string; description: string; inputSchema: Record<string, unknown> }> {
    return this.getAll().map(tool => ({
      name: tool.name,
      description: tool.description,
      inputSchema: zodToJsonSchema(tool.schema)
    }));
  }

  size(): number {
    return this.tools.size;
  }
}

export const registry = new ToolRegistry();
