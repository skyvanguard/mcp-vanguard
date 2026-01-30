# Changelog

All notable changes to mcp-vanguard will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.1.0] - 2025-01-30

### Added

#### New Tools
- `vanguard_ssl_check` - SSL/TLS certificate analysis with security grading
- `vanguard_cors_check` - CORS misconfiguration detection
- `vanguard_robots_sitemap` - Parse robots.txt and sitemap.xml
- `vanguard_js_endpoints` - Extract endpoints and secrets from JavaScript
- `vanguard_param_miner` - Hidden parameter discovery
- `vanguard_cve_lookup` - CVE database search (NVD)
- `vanguard_export_html` - Convert markdown reports to styled HTML

#### Infrastructure
- Global caching system for API responses
- Rate limiter with per-domain configuration
- ESLint and Prettier configuration
- GitHub Actions CI workflow
- Comprehensive documentation

### Changed
- Server version bumped to 1.1.0
- Improved tool descriptions
- Better error handling across all tools

## [1.0.0] - 2025-01-30

### Added

#### Core Features
- MCP Server implementation with stdio transport
- Windows/WSL bridge for Kali tools integration
- Scope management system
- Permission tiers (SAFE, DANGEROUS, BLOCKED)

#### Reconnaissance Tools
- `vanguard_subdomain_enum` - Subdomain enumeration via crt.sh
- `vanguard_port_scan` - Port scanning with nmap/TCP fallback
- `vanguard_whois` - WHOIS lookups via RDAP
- `vanguard_dns_records` - DNS record queries

#### Web Tools
- `vanguard_ffuf` - Web fuzzing integration
- `vanguard_nuclei_scan` - Vulnerability scanning
- `vanguard_headers_check` - Security headers analysis
- `vanguard_tech_detect` - Technology fingerprinting
- `vanguard_wayback` - Wayback Machine search

#### OSINT Tools
- `vanguard_cert_search` - Certificate transparency search
- `vanguard_github_dorks` - GitHub dork generation

#### Utility Tools
- `vanguard_set_scope` - Define authorized targets
- `vanguard_check_scope` - Verify scope
- `vanguard_generate_report` - Markdown report generation

### Security
- Scope enforcement on all active tools
- Permission-based tool access
- Rate limiting to prevent abuse
