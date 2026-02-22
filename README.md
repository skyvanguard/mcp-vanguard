# mcp-vanguard

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Node.js](https://img.shields.io/badge/Node.js-18+-green.svg)](https://nodejs.org/)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.0+-blue.svg)](https://www.typescriptlang.org/)
[![MCP](https://img.shields.io/badge/MCP-Compatible-purple.svg)](https://modelcontextprotocol.io/)
[![Tools](https://img.shields.io/badge/Tools-89-orange.svg)](#tools-89-total)
[![Tests](https://img.shields.io/badge/Tests-178-brightgreen.svg)](#development)

A security pentesting MCP Server with **89 tools** across **10 categories** for Claude integration. Features native **Windows/WSL bridge** for using Kali Linux tools from any terminal — zero new npm dependencies.

## Features

- **89 Security Tools** across 10 categories: recon, web, OSINT, network, exploit, crypto, cloud, container, analysis, and utilities
- **Registry Architecture**: Auto-discoverable tools with self-describing schemas, permissions, and execution modes
- **WSL Bridge**: Transparently execute Kali Linux tools (nmap, john, enum4linux, etc.) from Windows
- **Hybrid Execution**: Native Node.js, external APIs, WSL subprocesses, or automatic fallback
- **Scope Management**: Prevent scanning outside authorized targets
- **Permission Tiers**: SAFE (passive) / DANGEROUS (active, scope required) / BLOCKED (unknown)
- **Report Generation**: Markdown and JSON reports, diff comparisons, risk scoring
- **Attack Chain Detection**: Correlate findings across tools to identify multi-step attack paths
- **Security Hardening**: Input sanitization, command allowlists, audit logging, safe error handling
- **Caching & Rate Limiting**: Built-in controls for efficient and safe scanning

## Quick Start

```bash
git clone https://github.com/skyvanguard/mcp-vanguard.git
cd mcp-vanguard
npm install
npm run build
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

## Tools (89 total)

### Reconnaissance (4 tools)

| Tool | Description | Permission |
|------|-------------|------------|
| `vanguard_subdomain_enum` | Enumerate subdomains via crt.sh and DNS bruteforce | DANGEROUS |
| `vanguard_port_scan` | Port scanning with nmap or TCP connect fallback | DANGEROUS |
| `vanguard_whois` | WHOIS lookup for domains and IPs | SAFE |
| `vanguard_dns_records` | Query DNS records (A, AAAA, MX, NS, TXT, etc.) | SAFE |

### Web Security (10 tools)

| Tool | Description | Permission |
|------|-------------|------------|
| `vanguard_ffuf` | Web fuzzing with ffuf (FUZZ keyword) | DANGEROUS |
| `vanguard_nuclei_scan` | Vulnerability scanning with nuclei templates | DANGEROUS |
| `vanguard_param_miner` | Discover hidden HTTP parameters | DANGEROUS |
| `vanguard_headers_check` | Analyze security headers (HSTS, CSP, X-Frame-Options) | SAFE |
| `vanguard_tech_detect` | Technology fingerprinting (CMS, frameworks, CDN) | SAFE |
| `vanguard_wayback` | Wayback Machine URL history | SAFE |
| `vanguard_ssl_check` | SSL/TLS certificate and configuration analysis | SAFE |
| `vanguard_cors_check` | CORS misconfiguration detection | SAFE |
| `vanguard_robots_sitemap` | Parse robots.txt and sitemap.xml | SAFE |
| `vanguard_js_endpoints` | Extract endpoints and secrets from JavaScript | SAFE |

### Network & Infrastructure (15 tools)

| Tool | Description | Permission |
|------|-------------|------------|
| `vanguard_traceroute` | Trace network path to target | DANGEROUS |
| `vanguard_ping_sweep` | Discover live hosts in a network range | DANGEROUS |
| `vanguard_service_detect` | Detect services/versions with nmap -sV | DANGEROUS |
| `vanguard_os_detect` | OS fingerprinting with nmap | DANGEROUS |
| `vanguard_banner_grab` | Grab service banners via TCP | DANGEROUS |
| `vanguard_snmp_enum` | Enumerate SNMP data (WSL) | DANGEROUS |
| `vanguard_smb_enum` | Enumerate SMB shares and users (WSL) | DANGEROUS |
| `vanguard_ldap_enum` | Enumerate LDAP directory (WSL) | DANGEROUS |
| `vanguard_dns_zone_transfer` | Attempt DNS zone transfer (AXFR) | DANGEROUS |
| `vanguard_arp_scan` | ARP discovery on local network (WSL) | DANGEROUS |
| `vanguard_ftp_check` | Check FTP for anonymous access | SAFE |
| `vanguard_ssh_audit` | Audit SSH algorithms and configuration | SAFE |
| `vanguard_reverse_dns` | Reverse DNS (PTR) lookup | SAFE |
| `vanguard_network_cidr` | CIDR calculator and subnet operations | SAFE |
| `vanguard_http_methods` | Test allowed HTTP methods on a URL | SAFE |

### OSINT (15 tools)

| Tool | Description | Permission |
|------|-------------|------------|
| `vanguard_github_dorks` | Generate GitHub dork queries for sensitive data | DANGEROUS |
| `vanguard_cert_search` | Certificate transparency log search | SAFE |
| `vanguard_cve_lookup` | CVE database search (NVD) | SAFE |
| `vanguard_email_hunter` | Find email addresses for a domain | SAFE |
| `vanguard_social_media` | Check username across social platforms | SAFE |
| `vanguard_domain_reputation` | Domain/IP reputation check | SAFE |
| `vanguard_ip_geolocation` | IP geolocation (country, city, ISP, ASN) | SAFE |
| `vanguard_asn_lookup` | ASN lookup by number, IP, or organization | SAFE |
| `vanguard_google_dorks` | Generate Google dork queries for a target | SAFE |
| `vanguard_shodan_search` | Search Shodan for exposed services (API key required) | SAFE |
| `vanguard_breach_check` | Check email/domain in known data breaches | SAFE |
| `vanguard_metadata_extract` | Extract metadata from web pages | SAFE |
| `vanguard_dns_history` | Historical DNS record lookup | SAFE |
| `vanguard_favicon_hash` | Favicon hash for Shodan fingerprinting | SAFE |
| `vanguard_web_archive_diff` | Wayback Machine snapshot analysis | SAFE |

### Exploitation (10 tools)

| Tool | Description | Permission |
|------|-------------|------------|
| `vanguard_exploit_search` | Search exploits by product/CVE (searchsploit + APIs) | DANGEROUS |
| `vanguard_reverse_shell_gen` | Generate reverse shell payloads (bash, python, php, etc.) | DANGEROUS |
| `vanguard_sqli_test` | SQL injection testing (error, boolean, time, union) | DANGEROUS |
| `vanguard_xss_test` | Reflected XSS testing with multiple payloads | DANGEROUS |
| `vanguard_ssrf_test` | SSRF testing (localhost, cloud metadata, file://) | DANGEROUS |
| `vanguard_lfi_test` | Local File Inclusion (path traversal, PHP wrappers) | DANGEROUS |
| `vanguard_command_inject_test` | OS command injection testing | DANGEROUS |
| `vanguard_open_redirect_test` | Open redirect with bypass techniques | DANGEROUS |
| `vanguard_crlf_inject_test` | CRLF / HTTP header injection testing | DANGEROUS |
| `vanguard_deserialization_check` | Insecure deserialization detection (Java, PHP, .NET, Python) | DANGEROUS |

### Password & Crypto (8 tools)

| Tool | Description | Permission |
|------|-------------|------------|
| `vanguard_hash_crack` | Crack hashes with John the Ripper (WSL) | DANGEROUS |
| `vanguard_jwt_attack` | JWT vulnerabilities: none alg, weak secrets, alg confusion | DANGEROUS |
| `vanguard_password_gen` | Secure random passwords or CeWL-based wordlists | DANGEROUS |
| `vanguard_hash_identify` | Identify hash type (MD5, SHA, bcrypt, NTLM, etc.) | SAFE |
| `vanguard_password_policy` | Password strength analysis with entropy and crack time | SAFE |
| `vanguard_jwt_decode` | Decode JWT tokens with security checks | SAFE |
| `vanguard_crypto_audit` | HTTPS/TLS security headers and cookie audit | SAFE |
| `vanguard_base_decode` | Multi-format encode/decode (Base64, hex, URL, HTML, Unicode) | SAFE |

### Cloud Security (8 tools)

| Tool | Description | Permission |
|------|-------------|------------|
| `vanguard_cloud_metadata` | SSRF test for cloud metadata endpoints (AWS, GCP, Azure) | DANGEROUS |
| `vanguard_subdomain_takeover` | Dangling CNAME subdomain takeover detection | DANGEROUS |
| `vanguard_exposed_env_check` | Check for exposed .env, .git, config files | DANGEROUS |
| `vanguard_s3_bucket_check` | AWS S3 bucket public access check | SAFE |
| `vanguard_azure_blob_check` | Azure Blob Storage access check | SAFE |
| `vanguard_gcp_bucket_check` | Google Cloud Storage access check | SAFE |
| `vanguard_firebase_check` | Firebase project exposure check | SAFE |
| `vanguard_cloud_enum` | Enumerate cloud resources by keyword permutations | SAFE |

### Container Security (5 tools)

| Tool | Description | Permission |
|------|-------------|------------|
| `vanguard_docker_socket` | Check for exposed Docker daemon (TCP 2375/2376) | DANGEROUS |
| `vanguard_k8s_api` | Kubernetes API/Kubelet unauthenticated access check | DANGEROUS |
| `vanguard_container_escape` | Container escape vector detection (socket, caps, mounts) | DANGEROUS |
| `vanguard_registry_enum` | Docker Registry v2 repository/tag enumeration | DANGEROUS |
| `vanguard_helm_audit` | Helm chart security audit (privileged, capabilities, secrets) | SAFE |

### Analysis & Reporting (9 tools)

| Tool | Description | Permission |
|------|-------------|------------|
| `vanguard_vuln_correlate` | Cross-tool finding correlation and attack chain detection | SAFE |
| `vanguard_attack_surface` | Attack surface mapping from ports, techs, and subdomains | SAFE |
| `vanguard_risk_score` | Risk scoring with context multipliers | SAFE |
| `vanguard_remediation_plan` | Prioritized remediation plan generation | SAFE |
| `vanguard_encoding_detect` | Multi-layer encoding detection and decoding | SAFE |
| `vanguard_diff_report` | Before/after scan comparison (new, fixed, upgraded) | SAFE |
| `vanguard_timeline` | Pentest event timeline with phase analysis | SAFE |
| `vanguard_scope_manager` | Target scope management (set, add, remove, check) | SAFE |
| `vanguard_report_gen` | Security assessment reports in Markdown or JSON | SAFE |

### Utilities (5 tools)

| Tool | Description | Permission |
|------|-------------|------------|
| `vanguard_set_scope` | Define authorized target scope | SAFE |
| `vanguard_check_scope` | Verify if target is in scope | SAFE |
| `vanguard_generate_report` | Generate markdown security report | SAFE |
| `vanguard_export_html` | Convert report to styled HTML | SAFE |
| `vanguard_audit_stats` | View audit log and security events | SAFE |

### Summary

| Category | Tools | SAFE | DANGEROUS |
|----------|-------|------|-----------|
| Reconnaissance | 4 | 2 | 2 |
| Web Security | 10 | 7 | 3 |
| Network | 15 | 5 | 10 |
| OSINT | 15 | 14 | 1 |
| Exploitation | 10 | 0 | 10 |
| Crypto | 8 | 5 | 3 |
| Cloud | 8 | 5 | 3 |
| Container | 5 | 1 | 4 |
| Analysis | 9 | 9 | 0 |
| Utilities | 5 | 5 | 0 |
| **Total** | **89** | **53** | **36** |

## Permission Tiers

| Tier | Description | Example |
|------|-------------|---------|
| **SAFE** | Passive operations, no direct target interaction | DNS lookups, hash identification, report generation |
| **DANGEROUS** | Active scanning, requires target authorization | Port scans, injection testing, fuzzing |
| **BLOCKED** | Unregistered/unknown tools (rejected automatically) | — |

## Usage Examples

### 1. Set Scope

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
vanguard_asn_lookup for example.com
vanguard_favicon_hash for https://example.com
```

### 3. Security Analysis

```
vanguard_headers_check for https://example.com
vanguard_cors_check for https://api.example.com
vanguard_js_endpoints for https://example.com with deep: true
vanguard_cve_lookup for "nginx 1.20"
vanguard_crypto_audit for https://example.com
```

### 4. Active Scanning (requires authorization)

```
vanguard_subdomain_enum for example.com
vanguard_port_scan for example.com ports 1-1000
vanguard_service_detect for example.com ports [80, 443, 8080]
vanguard_nuclei_scan for https://example.com with severity ["high","critical"]
vanguard_sqli_test for https://example.com/search?q=test
vanguard_xss_test for https://example.com/search?q=test
```

### 5. Cloud & Container Checks

```
vanguard_s3_bucket_check for "company-backup"
vanguard_firebase_check for "my-project"
vanguard_subdomain_takeover for ["app.example.com", "api.example.com"]
vanguard_docker_socket for 10.0.0.5
vanguard_k8s_api for https://10.0.0.5:6443
```

### 6. Analysis & Reporting

```
vanguard_vuln_correlate with findings from multiple scans
vanguard_risk_score with context (public, auth, sensitive data)
vanguard_remediation_plan from findings
vanguard_diff_report comparing before/after scans
vanguard_report_gen with title "Security Assessment" and findings
```

## Development

```bash
npm install        # Install dependencies
npm run build      # Build TypeScript
npm run dev        # Watch mode
npm test           # Run 178 tests
npm run test:coverage  # Coverage report
npm run format     # Format code
```

## Security Features

### Input Sanitization
- Shell metacharacter filtering
- Path traversal prevention
- URL validation (no credentials, no private IPs)
- Domain/IP format validation

### Command Execution Safety
- **Command Allowlist**: Only permitted commands can execute via WSL or Windows
- **Argument Escaping**: All arguments are properly escaped for shell execution
- **Timeout Protection**: Configurable timeouts per command

### Audit Logging
- All tool calls are logged with timestamps and duration
- Security events (blocked commands, scope violations) are tracked
- Rate limit violations are recorded
- View logs via `vanguard_audit_stats`

### Safe Error Handling
- Error messages are sanitized to prevent info leakage
- Paths, IPs, and sensitive data are masked in error output
- Stack traces are removed from user-facing errors

## Architecture

```
mcp-vanguard/
├── src/
│   ├── index.ts              # Entry point
│   ├── server.ts             # MCP server + tool registration
│   ├── registry.ts           # ToolRegistry (auto-discover, permissions)
│   ├── config.ts             # Configuration + scope management
│   ├── types/
│   │   └── tool.ts           # ToolDefinition interface
│   ├── executor/
│   │   ├── windows.ts        # Windows executor (with allowlist)
│   │   └── wsl.ts            # WSL bridge (with allowlist)
│   ├── tools/
│   │   ├── recon/            # 4 reconnaissance tools
│   │   ├── web/              # 10 web security tools
│   │   ├── network/          # 15 network/infrastructure tools
│   │   ├── osint/            # 15 OSINT tools
│   │   ├── exploit/          # 10 exploitation tools
│   │   ├── crypto/           # 8 password & crypto tools
│   │   ├── cloud/            # 8 cloud security tools
│   │   ├── container/        # 5 container security tools
│   │   ├── analysis/         # 9 analysis & reporting tools
│   │   └── utils/            # 5 utility tools
│   └── utils/
│       ├── cache.ts          # Response caching
│       ├── rate-limiter.ts   # Rate limiting
│       ├── sanitizer.ts      # Input sanitization
│       ├── audit.ts          # Audit logging
│       ├── safe-error.ts     # Safe error handling
│       └── zod-to-json.ts    # Zod schema → JSON Schema
├── tests/                    # 178 Vitest tests
├── dist/                     # Compiled output
└── package.json
```

## Requirements

| Requirement | Version |
|-------------|---------|
| Node.js | 18+ |
| TypeScript | 5.0+ (dev) |

**Optional (for active scanning via WSL):**
- nmap, ffuf, nuclei, dig, john, enum4linux, smbclient, ldapsearch, ssh-audit, arp-scan, snmpwalk, cewl, searchsploit

## Legal Disclaimer

**WARNING**: Unauthorized access to computer systems is illegal. This tool is for **authorized security testing only**. Always obtain proper written authorization before scanning any target. The authors accept no liability for misuse.

## License

MIT License — see [LICENSE](LICENSE) for details.

## Author

[@skyvanguard](https://github.com/skyvanguard)
