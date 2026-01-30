# mcp-vanguard

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Node.js](https://img.shields.io/badge/Node.js-18+-green.svg)](https://nodejs.org/)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.0+-blue.svg)](https://www.typescriptlang.org/)
[![MCP](https://img.shields.io/badge/MCP-Compatible-purple.svg)](https://modelcontextprotocol.io/)

A security pentesting MCP Server that integrates offensive security tools with Claude. Features native **Windows/WSL bridge** for using Kali tools from any terminal.

## Features

- **22 Security Tools**: Reconnaissance, web pentesting, OSINT, and utilities
- **WSL Bridge**: Transparently execute Kali Linux tools from Windows
- **Scope Management**: Prevent scanning outside authorized targets
- **Report Generation**: Markdown and HTML reports with security themes
- **Caching & Rate Limiting**: Built-in controls for efficient and safe scanning
- **Structured Output**: Parsed results, not raw text
- **Security Hardening**: Input sanitization, command allowlists, audit logging, safe error handling

## Quick Start

```bash
# Clone the repository
git clone https://github.com/skyvanguard/mcp-vanguard.git
cd mcp-vanguard

# Install dependencies
npm install

# Build
npm run build

# Run tests
npm test
```

## Configuration

Add to your Claude MCP configuration:

**Claude Desktop** (`~/.claude/claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "vanguard": {
      "command": "node",
      "args": ["/path/to/mcp-vanguard/dist/index.js"]
    }
  }
}
```

**Claude Code** (`.mcp.json` in project root):

```json
{
  "mcpServers": {
    "vanguard": {
      "command": "node",
      "args": ["C:/path/to/mcp-vanguard/dist/index.js"]
    }
  }
}
```

## Tools (22 total)

### Reconnaissance (4 tools)

| Tool | Description | Permission |
|------|-------------|------------|
| `vanguard_subdomain_enum` | Enumerate subdomains via crt.sh and DNS brute | 🔴 DANGEROUS |
| `vanguard_port_scan` | Port scanning (nmap or TCP connect) | 🔴 DANGEROUS |
| `vanguard_whois` | WHOIS lookup for domains/IPs | 🟢 SAFE |
| `vanguard_dns_records` | Query DNS records (A, AAAA, MX, etc.) | 🟢 SAFE |

### Web Security (10 tools)

| Tool | Description | Permission |
|------|-------------|------------|
| `vanguard_ffuf` | Web fuzzing with ffuf | 🔴 DANGEROUS |
| `vanguard_nuclei_scan` | Vulnerability scanning with nuclei | 🔴 DANGEROUS |
| `vanguard_headers_check` | Security headers analysis | 🟢 SAFE |
| `vanguard_tech_detect` | Technology fingerprinting | 🟢 SAFE |
| `vanguard_wayback` | Wayback Machine URL history | 🟢 SAFE |
| `vanguard_ssl_check` | SSL/TLS certificate analysis | 🟢 SAFE |
| `vanguard_cors_check` | CORS misconfiguration detection | 🟢 SAFE |
| `vanguard_robots_sitemap` | Parse robots.txt and sitemap.xml | 🟢 SAFE |
| `vanguard_js_endpoints` | Extract endpoints from JavaScript | 🟢 SAFE |
| `vanguard_param_miner` | Discover hidden parameters | 🔴 DANGEROUS |

### OSINT (3 tools)

| Tool | Description | Permission |
|------|-------------|------------|
| `vanguard_cert_search` | Certificate transparency search | 🟢 SAFE |
| `vanguard_github_dorks` | GitHub dork query generation | 🔴 DANGEROUS |
| `vanguard_cve_lookup` | CVE database search (NVD) | 🟢 SAFE |

### Utilities (5 tools)

| Tool | Description | Permission |
|------|-------------|------------|
| `vanguard_set_scope` | Define authorized targets | 🟢 SAFE |
| `vanguard_check_scope` | Verify target is in scope | 🟢 SAFE |
| `vanguard_generate_report` | Generate markdown report | 🟢 SAFE |
| `vanguard_export_html` | Convert to styled HTML | 🟢 SAFE |
| `vanguard_audit_stats` | View audit log and security events | 🟢 SAFE |

## Permission Tiers

| Tier | Description | Example |
|------|-------------|---------|
| 🟢 **SAFE** | Passive reconnaissance, no direct target interaction | DNS lookups, WHOIS |
| 🔴 **DANGEROUS** | Active scanning, requires target authorization | Port scans, fuzzing |
| ⛔ **BLOCKED** | Destructive tools (disabled by default) | - |

## Usage Examples

### 1. Set Scope First

```
vanguard_set_scope with targets: ["example.com", "*.example.com"]
```

### 2. Passive Reconnaissance

```
vanguard_dns_records for example.com
vanguard_cert_search for example.com
vanguard_wayback for example.com
vanguard_ssl_check for example.com
vanguard_tech_detect for https://example.com
```

### 3. Security Analysis

```
vanguard_headers_check for https://example.com
vanguard_cors_check for https://api.example.com
vanguard_js_endpoints for https://example.com with deep: true
vanguard_cve_lookup for "nginx 1.20"
```

### 4. Active Scanning (requires authorization)

```
vanguard_subdomain_enum for example.com
vanguard_port_scan for example.com ports 1-1000
vanguard_nuclei_scan for https://example.com with severity ["high","critical"]
vanguard_param_miner for https://example.com/search
```

### 5. Generate Report

```
vanguard_generate_report with title "Security Assessment" and findings
vanguard_export_html with theme "security"
```

## Examples

See the [examples/](examples/) directory for detailed workflows:

- [Basic Reconnaissance](examples/basic-recon.md)
- [Web Security Audit](examples/web-security-audit.md)
- [Bug Bounty Workflow](examples/bug-bounty-workflow.md)

## Development

```bash
# Install dependencies
npm install

# Build
npm run build

# Watch mode
npm run dev

# Run tests
npm test

# Test with coverage
npm run test:coverage

# Lint
npm run lint

# Format
npm run format
```

## Security Features

mcp-vanguard implements defense-in-depth security measures:

### Input Sanitization
- Shell metacharacter filtering
- Path traversal prevention
- URL validation (no credentials, no private IPs)
- Domain/IP format validation

### Command Execution Safety
- **Command Allowlist**: Only permitted commands can execute
  - Windows: `nmap`, `ffuf`, `nuclei`, `ping`, `tracert`, `curl`, etc.
  - WSL: `nmap`, `ffuf`, `nuclei`, `whois`, `dig`, `curl`, etc.
- **Argument Escaping**: All arguments are properly escaped for shell execution
- **Timeout Protection**: Commands have configurable timeouts

### Audit Logging
- All tool calls are logged with timestamps and duration
- Security events (blocked commands, scope violations) are tracked
- Rate limit violations are recorded
- View logs via `vanguard_audit_stats`

### Safe Error Handling
- Error messages are sanitized to prevent info leakage
- Paths, IPs, and sensitive data are masked in error output
- Stack traces are removed from user-facing errors

## Project Structure

```
mcp-vanguard/
├── src/
│   ├── index.ts              # Entry point
│   ├── server.ts             # MCP server (22 tools)
│   ├── config.ts             # Configuration + permissions
│   ├── executor/
│   │   ├── windows.ts        # Windows executor (with allowlist)
│   │   └── wsl.ts            # WSL bridge (with allowlist)
│   ├── tools/
│   │   ├── recon/            # 4 reconnaissance tools
│   │   ├── web/              # 10 web security tools
│   │   ├── osint/            # 3 OSINT tools
│   │   └── utils/            # 5 utility tools
│   └── utils/
│       ├── cache.ts          # Response caching
│       ├── rate-limiter.ts   # Rate limiting
│       ├── sanitizer.ts      # Input sanitization
│       ├── audit.ts          # Audit logging
│       └── safe-error.ts     # Safe error handling
├── tests/                    # 89 Vitest tests
├── examples/                 # Usage examples
├── dist/                     # Compiled output
└── package.json
```

## Requirements

| Requirement | Version |
|-------------|---------|
| Node.js | 18+ |
| TypeScript | 5.0+ (dev) |

**Optional (for active scanning):**
- nmap (Windows or WSL)
- ffuf (Windows or WSL)
- nuclei (Windows or WSL)

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## Security

See [SECURITY.md](SECURITY.md) for vulnerability reporting.

## Legal Disclaimer

⚠️ **WARNING**: Unauthorized access to computer systems is illegal. This tool is for authorized security testing only. Always obtain proper authorization before scanning.

## License

MIT License - see [LICENSE](LICENSE) for details.

## Author

[@skyvanguard](https://github.com/skyvanguard)

---

<p align="center">
  Made with ❤️ for the security community
</p>
