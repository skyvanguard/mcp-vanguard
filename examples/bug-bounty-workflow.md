# Bug Bounty Workflow Example

A typical bug bounty reconnaissance workflow using mcp-vanguard.

## Phase 1: Scope Definition

```
vanguard_set_scope with targets: [
  "*.target.com",
  "api.target.com",
  "app.target.com"
]
```

## Phase 2: Asset Discovery

### 2.1 Subdomain Enumeration

```
vanguard_subdomain_enum for target.com with useCrtsh: true, useDnsBrute: true
```

### 2.2 Certificate Transparency

```
vanguard_cert_search for target.com with includeSubdomains: true
```

### 2.3 Wayback Machine

```
vanguard_wayback for target.com with limit: 5000
```

Look for interesting paths in historical URLs:
- `/api/`
- `/admin/`
- `/backup/`
- `.env`
- `.git/`

## Phase 3: Technology Fingerprinting

For each discovered subdomain:

```
vanguard_tech_detect for https://subdomain.target.com
```

## Phase 4: Security Analysis

### 4.1 Security Headers

```
vanguard_headers_check for https://target.com
```

### 4.2 CORS Testing

```
vanguard_cors_check for https://api.target.com
```

### 4.3 JavaScript Analysis

```
vanguard_js_endpoints for https://app.target.com with deep: true
```

Look for:
- Hidden API endpoints
- Hardcoded secrets
- Internal URLs
- Debug comments

## Phase 5: Active Testing (if authorized)

### 5.1 Parameter Discovery

```
vanguard_param_miner for https://target.com/search with wordlist: "extended"
```

### 5.2 Directory Fuzzing

```
vanguard_ffuf for https://target.com/FUZZ with wordlist: "common"
```

### 5.3 Vulnerability Scanning

```
vanguard_nuclei_scan for https://target.com with:
  severity: ["high", "critical"]
  tags: ["cve", "misconfig"]
```

## Phase 6: CVE Research

For each identified technology:

```
vanguard_cve_lookup for "wordpress 6.0" with severity: ["HIGH", "CRITICAL"]
```

## Phase 7: GitHub Recon

```
vanguard_github_dorks for target.com with:
  searchType: "domain"
  dorkCategories: ["secrets", "api_keys", "configs"]
```

Manually review the generated search URLs.

## Phase 8: Report Generation

### Markdown Report

```
vanguard_generate_report with:
  title: "Bug Bounty Report - target.com"
  target: "target.com"
  findings: [
    {
      title: "CORS Misconfiguration",
      severity: "high",
      description: "...",
      evidence: "...",
      remediation: "..."
    }
  ]
  methodology: [
    "Subdomain enumeration via crt.sh",
    "Technology fingerprinting",
    "Security headers analysis",
    "Active vulnerability scanning"
  ]
```

### HTML Report

```
vanguard_export_html with:
  title: "Bug Bounty Report - target.com"
  content: "<markdown from above>"
  theme: "security"
```

## Tips

1. **Take Notes**: Document everything as you go
2. **Verify Findings**: Always manually verify before reporting
3. **Check Scope**: Ensure each target is in scope
4. **Be Ethical**: Don't exploit vulnerabilities
5. **Quality > Quantity**: Well-documented findings get rewarded
