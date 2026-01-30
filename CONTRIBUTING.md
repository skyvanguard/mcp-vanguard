# Contributing to mcp-vanguard

Thank you for your interest in contributing to mcp-vanguard! This document provides guidelines for contributing.

## Getting Started

1. Fork the repository
2. Clone your fork:
   ```bash
   git clone https://github.com/YOUR_USERNAME/mcp-vanguard.git
   cd mcp-vanguard
   ```
3. Install dependencies:
   ```bash
   npm install
   ```
4. Create a feature branch:
   ```bash
   git checkout -b feature/your-feature-name
   ```

## Development

### Building

```bash
npm run build
```

### Watch mode

```bash
npm run dev
```

### Testing locally with Claude

Add to your MCP configuration:

```json
{
  "mcpServers": {
    "vanguard-dev": {
      "command": "node",
      "args": ["/path/to/mcp-vanguard/dist/index.js"]
    }
  }
}
```

## Adding New Tools

1. Create a new file in the appropriate category under `src/tools/`:
   - `recon/` - Reconnaissance tools
   - `web/` - Web pentesting tools
   - `osint/` - OSINT tools
   - `utils/` - Utility tools

2. Follow this template:

```typescript
import { z } from 'zod';

// Define input schema with Zod
export const myToolSchema = z.object({
  target: z.string().describe('Target description'),
  option: z.boolean().default(false).describe('Option description')
});

export type MyToolInput = z.infer<typeof myToolSchema>;

// Implement the tool function
export async function myTool(input: MyToolInput): Promise<{
  success: boolean;
  // ... your result type
}> {
  // Implementation
}
```

3. Register the tool in `src/server.ts`:
   - Import the schema and function
   - Add to the `tools` array
   - Add a case in the switch statement
   - Set permission tier in `src/config.ts`

## Permission Tiers

When adding tools, assign appropriate permission:

- **SAFE**: Passive reconnaissance, no direct interaction with target
- **DANGEROUS**: Active scanning, requires explicit authorization
- **BLOCKED**: Destructive operations (avoid adding these)

## Code Style

- Use TypeScript strict mode
- Prefer async/await over callbacks
- Add descriptive JSDoc comments for public functions
- Use meaningful variable names

## Commit Messages

Follow conventional commits:

```
feat: add new subdomain enumeration source
fix: handle timeout in port scanner
docs: update README with new examples
refactor: simplify DNS query logic
```

## Pull Request Process

1. Ensure your code builds without errors
2. Update documentation if needed
3. Add your tool to the README table
4. Create a PR with a clear description
5. Wait for review

## Reporting Issues

When reporting bugs, include:

- Node.js version
- Operating system (Windows/Linux/macOS)
- Steps to reproduce
- Expected vs actual behavior
- Error messages/logs

## Security

If you discover a security vulnerability, please **do not** open a public issue. Instead, email the maintainer directly or use GitHub's private vulnerability reporting.

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
