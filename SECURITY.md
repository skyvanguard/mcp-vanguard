# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.x.x   | :white_check_mark: |

## Reporting a Vulnerability

If you discover a security vulnerability in mcp-vanguard, please report it responsibly:

1. **Do NOT** open a public GitHub issue
2. Use GitHub's [private vulnerability reporting](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing/privately-reporting-a-security-vulnerability)
3. Or email the maintainer directly

### What to Include

- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

### Response Timeline

- Initial response: 48 hours
- Status update: 7 days
- Fix timeline: Depends on severity

## Security Considerations

### This Tool's Purpose

mcp-vanguard is designed for **authorized security testing only**. Users are responsible for:

- Obtaining proper authorization before testing
- Staying within defined scope
- Following applicable laws and regulations

### Built-in Protections

- **Scope Management**: Tools check targets against defined scope
- **Permission Tiers**: Dangerous tools require explicit confirmation
- **Rate Limiting**: Built-in controls to prevent abuse
- **Command Allowlists**: Only permitted commands can execute via executors
- **Input Sanitization**: Shell metacharacters and path traversal attempts are blocked
- **Audit Logging**: All tool calls and security events are logged
- **Safe Error Handling**: Sensitive data is masked in error messages

### Security Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        MCP Server                                │
├─────────────────────────────────────────────────────────────────┤
│  Input Validation     │  Permission Check   │  Scope Validation │
│  (sanitizer.ts)       │  (config.ts)        │  (config.ts)      │
├─────────────────────────────────────────────────────────────────┤
│                     Audit Logging (audit.ts)                     │
├─────────────────────────────────────────────────────────────────┤
│  Command Allowlist    │  Arg Escaping       │  Safe Error       │
│  (executor/*.ts)      │  (sanitizer.ts)     │  (safe-error.ts)  │
└─────────────────────────────────────────────────────────────────┘
```

### Command Allowlists

**Windows Executor** (`executeWindows`):
- nmap, ffuf, nuclei, where, ping, tracert, nslookup, ipconfig, netstat, curl, powershell

**WSL Executor** (`executeWSL`):
- nmap, ffuf, nuclei, whois, dig, host, curl, wget, ping, traceroute, which, echo

Any command not in the allowlist will be blocked and logged as a security event.

### Safe Usage Guidelines

1. Always set scope before testing:
   ```
   vanguard_set_scope with targets: ["authorized-target.com"]
   ```

2. Use passive tools first (SAFE tier)
3. Only use active tools (DANGEROUS tier) with authorization
4. Never use against production systems without permission

## Legal Disclaimer

Unauthorized access to computer systems is illegal. This tool is provided for educational and authorized testing purposes only. The authors are not responsible for misuse.
