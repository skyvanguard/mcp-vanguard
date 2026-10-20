import { describe, it, expect, afterEach, vi } from 'vitest';
import { setScope } from '../src/config.js';

import { certSearchSchema, certSearch } from '../src/tools/osint/certs.js';
import { emailHunterSchema, emailHunter } from '../src/tools/osint/email-hunter.js';
import { domainReputationSchema, domainReputation } from '../src/tools/osint/domain-reputation.js';
import { ipGeolocationSchema, ipGeolocation } from '../src/tools/osint/ip-geolocation.js';
import { dnsHistorySchema, dnsHistory } from '../src/tools/osint/dns-history.js';
import { webArchiveDiffSchema, webArchiveDiff } from '../src/tools/osint/web-archive-diff.js';
import { breachCheckSchema, breachCheck } from '../src/tools/osint/breach-check.js';
import { asnLookupSchema, asnLookup } from '../src/tools/osint/asn-lookup.js';
import { shodanSearchSchema, shodanSearch } from '../src/tools/osint/shodan-search.js';
import { whoisSchema, whoisLookup } from '../src/tools/recon/whois.js';
import { dnsRecordsSchema, dnsRecords } from '../src/tools/recon/dns.js';
import { waybackSchema, waybackSearch } from '../src/tools/web/wayback.js';

const OUT_OF_SCOPE_DOMAIN = 'attacker.test';
const OUT_OF_SCOPE_IP = '198.51.100.7'; // TEST-NET-3, never in scope here

const blocked: Array<{ name: string; run: () => Promise<{ success: boolean; error?: string }> }> = [
  { name: 'cert_search', run: () => certSearch(certSearchSchema.parse({ domain: OUT_OF_SCOPE_DOMAIN })) },
  { name: 'email_hunter', run: () => emailHunter(emailHunterSchema.parse({ domain: OUT_OF_SCOPE_DOMAIN })) },
  { name: 'domain_reputation', run: () => domainReputation(domainReputationSchema.parse({ domain: OUT_OF_SCOPE_DOMAIN })) },
  { name: 'ip_geolocation', run: () => ipGeolocation(ipGeolocationSchema.parse({ ip: OUT_OF_SCOPE_IP })) },
  { name: 'dns_history', run: () => dnsHistory(dnsHistorySchema.parse({ domain: OUT_OF_SCOPE_DOMAIN })) },
  { name: 'web_archive_diff', run: () => webArchiveDiff(webArchiveDiffSchema.parse({ url: `http://${OUT_OF_SCOPE_DOMAIN}/` })) },
  { name: 'whois', run: () => whoisLookup(whoisSchema.parse({ target: OUT_OF_SCOPE_DOMAIN })) },
  { name: 'dns_records', run: () => dnsRecords(dnsRecordsSchema.parse({ domain: OUT_OF_SCOPE_DOMAIN })) },
  { name: 'wayback', run: () => waybackSearch(waybackSchema.parse({ domain: OUT_OF_SCOPE_DOMAIN })) },
  { name: 'breach_check (email -> domain)', run: () => breachCheck(breachCheckSchema.parse({ query: `user@${OUT_OF_SCOPE_DOMAIN}`, queryType: 'email' })) },
  { name: 'asn_lookup (IP query)', run: () => asnLookup(asnLookupSchema.parse({ query: OUT_OF_SCOPE_IP })) },
  { name: 'shodan_search (host mode)', run: () => shodanSearch(shodanSearchSchema.parse({ query: OUT_OF_SCOPE_IP, searchType: 'host' })) }
];

describe('scope enforcement on passive OSINT tools', () => {
  afterEach(() => {
    setScope([]);
    vi.restoreAllMocks();
  });

  for (const { name, run } of blocked) {
    it(`${name} refuses an out-of-scope target without any network call`, async () => {
      const fetchSpy = vi.spyOn(globalThis, 'fetch');
      setScope(['example.com']);

      const result = await run();

      expect(result.success).toBe(false);
      expect(result.error ?? '').toContain('not in scope');
      expect(fetchSpy).not.toHaveBeenCalled();
    });
  }
});

describe('scope gate does NOT over-block non-host inputs', () => {
  afterEach(() => {
    setScope([]);
    vi.restoreAllMocks();
  });

  it('asn_lookup allows a non-IP ASN query even when a scope is set', async () => {
    vi.spyOn(globalThis, 'fetch').mockRejectedValue(new Error('network disabled in test'));
    setScope(['example.com']);

    const result = await asnLookup(asnLookupSchema.parse({ query: 'AS13335' }));

    expect(result.error ?? '').not.toContain('not in scope');
  });

  it('shodan_search allows a free-form search query even when a scope is set', async () => {
    // No API key is configured in tests, so it returns the api-key error, not a scope error.
    setScope(['example.com']);

    const result = await shodanSearch(shodanSearchSchema.parse({ query: 'apache port:8080', searchType: 'search' }));

    expect(result.error ?? '').not.toContain('not in scope');
  });
});
