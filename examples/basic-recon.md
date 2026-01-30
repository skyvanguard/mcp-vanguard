# Basic Reconnaissance Example

This example shows how to perform basic passive reconnaissance on a target.

## 1. Set the Scope

Always start by defining your authorized targets:

```
vanguard_set_scope with targets: ["example.com", "*.example.com"]
```

## 2. DNS Enumeration

Get all DNS records:

```
vanguard_dns_records for example.com with recordTypes: ["A", "AAAA", "MX", "NS", "TXT"]
```

## 3. WHOIS Lookup

Get domain registration information:

```
vanguard_whois for example.com
```

## 4. Certificate Transparency

Find subdomains via certificate logs:

```
vanguard_cert_search for example.com
```

## 5. Wayback URLs

Discover historical URLs:

```
vanguard_wayback for example.com
```

## 6. Generate Report

Create a markdown report with your findings:

```
vanguard_generate_report with:
  title: "Passive Recon - example.com"
  target: "example.com"
  findings: [...]
```

## Expected Output

Each tool returns structured JSON data that can be easily parsed and analyzed.
