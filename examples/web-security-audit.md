# Web Security Audit Example

This example demonstrates a comprehensive web security audit workflow.

## 1. Set Scope

```
vanguard_set_scope with targets: ["target.com"]
```

## 2. Technology Detection

Identify what technologies the target uses:

```
vanguard_tech_detect for https://target.com
```

Example output:
```json
{
  "technologies": [
    { "name": "Nginx", "category": "Web Server", "confidence": 100 },
    { "name": "React", "category": "JavaScript Framework", "confidence": 85 },
    { "name": "Cloudflare", "category": "CDN", "confidence": 90 }
  ]
}
```

## 3. Security Headers Check

Analyze HTTP security headers:

```
vanguard_headers_check for https://target.com
```

Example output:
```json
{
  "score": 75,
  "grade": "B",
  "securityHeaders": [
    { "name": "Strict-Transport-Security", "present": true, "grade": "good" },
    { "name": "Content-Security-Policy", "present": false, "grade": "bad" }
  ]
}
```

## 4. SSL/TLS Analysis

Check certificate and TLS configuration:

```
vanguard_ssl_check for target.com
```

## 5. CORS Configuration

Test for CORS misconfigurations:

```
vanguard_cors_check for https://target.com
```

## 6. Robots.txt & Sitemap

Find interesting paths:

```
vanguard_robots_sitemap for https://target.com
```

## 7. JavaScript Analysis

Extract endpoints from JavaScript files:

```
vanguard_js_endpoints for https://target.com with deep: true
```

## 8. CVE Lookup

Search for known vulnerabilities in detected technologies:

```
vanguard_cve_lookup for "nginx 1.18" with severity: ["HIGH", "CRITICAL"]
```

## 9. Generate HTML Report

Create a professional HTML report:

```
vanguard_generate_report with findings...
vanguard_export_html with theme: "security"
```

## Best Practices

1. Always get authorization before testing
2. Start with passive tools (SAFE tier)
3. Document all findings
4. Verify false positives manually
5. Generate reports for stakeholders
